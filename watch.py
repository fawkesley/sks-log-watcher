#!/usr/bin/env python3

import csv
import datetime
import glob
import gzip
import logging
import io
import os
import re
import shutil
import sys
import tempfile
import subprocess

from os.path import dirname, join as pjoin

import backoff
import requests

from utcdatetime import utcdatetime

LOG_GLOB = os.environ['LOG_GLOB']
LOG_PATTERN = r'.*sks\[\d+\]: (?P<date>\d+-\d+-\d+) (?P<time>\d+:\d+:\d+) Adding hash (?P<hash>[A-F0-9]{32})\n$'  # noqa

KEYSERVER_URL = os.environ['KEYSERVER_URL']

EXPIRYBOT_API_URL = os.environ['EXPIRYBOT_API_URL']
EXPIRYBOT_API_TOKEN = os.environ['EXPIRYBOT_API_TOKEN']

CACHE_CSV = pjoin(dirname(__file__), 'hashes_processed.csv')
DEBUG_DIR = pjoin(dirname(__file__), 'failed_keys')


class HashNoLongerExists(ValueError):
    pass


def backoff_slow():
    for delay in (3, 5, 10, 10):
        yield delay


class HashCache():
    def __init__(self, filename):
        self._fn = filename
        self._hashes = set()

        self.load()

    def add_hash(self, hash_, updated):
        """
        Record the hash against its most recent updated (if the hash is already
        in the cache, record the most recent updated_at)
        """

        assert hash_ not in self
        assert hash_ not in self._hashes

        with io.open(self._fn, 'a') as f:
            writer = self._make_csv_writer(f)
            writer.writerow({
                'hash': hash_,
                'log_datetime': updated,
            })

        self._hashes.add(hash_)

    def load(self):
        try:
            with io.open(self._fn, 'r') as f:
                for row in csv.DictReader(f):
                    self._hashes.add(row['hash'])

        except FileNotFoundError:
            self._create_new_csv()

        logging.info("Loaded {} hashes".format(len(self._hashes)))

    def _create_new_csv(self):
        with io.open(self._fn, 'w') as f:
            csv_writer = self._make_csv_writer(f)
            csv_writer.writeheader()

    def _make_csv_writer(self, f):
        return csv.DictWriter(f, fieldnames=['hash', 'log_datetime'])

    def __contains__(self, hash_):
        return hash_ in self._hashes


def main(log_files):

    log_files = log_files or glob.glob(LOG_GLOB)

    logging.info('Opening {}'.format(log_files))

    hash_count, success_count, partial_count, fail_count = (0, 0, 0, 0)

    cache = HashCache(CACHE_CSV)

    seven_days_ago = datetime.datetime.now() - datetime.timedelta(days=7)

    for updated_at, hash_ in parse_log_files(log_files):
        hash_count += 1

        if updated_at < seven_days_ago:
            continue

        if hash_ in cache:
            continue

        try:
            fingerprint = get_fingerprint_from_hash(hash_)
            logging.info('Hash {} has fingerprint {}'.format(
                hash_, fingerprint))
            success_count += 1

        except HashNoLongerExists as e:
            logging.warn("'hash {} no longer exists in keyserver".format(e))
            fingerprint = None
            partial_count += 1

        except Exception as e:
            fingerprint = None
            logging.exception(e)
            fail_count += 1

        send_key_updated_message(hash_, fingerprint, updated_at)
        cache.add_hash(hash_, updated_at)

    message = (
        'Processed {} new hashes, {} without fingerprint, {} failed '
        '({} hashes total)'
    ).format(success_count, partial_count, fail_count, hash_count)

    if fail_count > 0:
        raise RuntimeError(message)
    else:
        logging.info(message)
        sys.exit(0)


def parse_log_files(log_files):
    for filename in log_files:
        with flexible_open(filename, 'rb') as f:
            for line in f.readlines():

                parsed = parse_line(line)
                if parsed:
                    updated_at, hash_ = parsed
                    yield (updated_at, hash_)


def flexible_open(filename, *args, **kwargs):
    if filename.endswith('.gz'):
        return gzip.open(filename, *args, **kwargs)
    else:
        return io.open(filename, *args, **kwargs)


def parse_line(line_bytes):
    if not line_bytes:
        return

    match = re.search(LOG_PATTERN.encode('utf-8'), line_bytes)

    if match:
        utc_format = '{date}T{time}Z'.format(
            date=match.group('date').decode('ascii'),
            time=match.group('time').decode('ascii'),
        )

        return (
            utcdatetime.from_string(utc_format),
            match.group('hash').decode('ascii')
        )


@backoff.on_exception(backoff_slow,
                      requests.exceptions.RequestException,
                      max_tries=4)
def get_fingerprint_from_hash(hash_):
    url = '{}/pks/lookup?search={}&op=hget&options=mr'.format(
        KEYSERVER_URL, hash_
    )

    with tempfile.NamedTemporaryFile('w') as f:
        response = requests.get(url)
        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError:
            NO_HASH_ERROR = 'Error handling request: Requested hash not found'

            if response.status_code == 500 and NO_HASH_ERROR in response.text:
                raise HashNoLongerExists(hash_)
            else:
                raise

        f.write(response.text)
        f.flush()

        command = [
            '/usr/bin/gpg2',
            '--batch',
            '--no-tty',
            f.name
        ]

        try:
            stdout = stdout_for_subprocess(command)
        except SubprocessError as e:
            copy_temp_file_for_debugging(f.name, hash_, e.stderr)
            raise

    return find_fingerprint(stdout)


def find_fingerprint(gpg_stdout):
    pattern = 'Key fingerprint = (?P<fingerprint>[A-F0-9 ]{50})'
    match = re.search(pattern, gpg_stdout)
    if match:
        return match.group('fingerprint')
    else:
        raise ValueError('No fingerprint line in GPG output: {}'.format(
            gpg_stdout))


def copy_temp_file_for_debugging(temp_filename, hash_, stderr):
    key_filename = pjoin(DEBUG_DIR, '{}.asc'.format(hash_))
    shutil.copy(temp_filename, key_filename)

    error_filename = pjoin(DEBUG_DIR, '{}_stderr.txt'.format(hash_))

    with io.open(error_filename, 'wb') as f:
        f.write(stderr)

    logging.info('Wrote debug file {}'.format(key_filename))


@backoff.on_exception(backoff.constant,
                      requests.exceptions.RequestException,
                      interval=10, max_tries=6)
def send_key_updated_message(sks_hash, fingerprint, updated_at):
    """
    Tell the API the given fingerprint was updated with the datetime.
    """

    if fingerprint is not None:
        fingerprint = fingerprint.upper().replace(' ', '')

    response = requests.post(
        EXPIRYBOT_API_URL,
        data={
            'sks_hash': sks_hash,
            'fingerprint': fingerprint,
            'updated_at': updated_at
        },
        headers={
            'Authorization': 'Token {}'.format(EXPIRYBOT_API_TOKEN),
        }
    )
    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError:
        logging.warn(response.text)
        raise


class SubprocessError(RuntimeError):
    def __init__(self, return_code, stdout, stderr):
        self.return_code = return_code
        self.stdout = stdout
        self.stderr = stderr


def stdout_for_subprocess(cmd_parts):
    logging.debug('Running {}'.format(' '.join(cmd_parts)))
    p = subprocess.Popen(
        cmd_parts,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    try:
        stdout, stderr = p.communicate(timeout=5)

    except subprocess.TimeoutExpired as e:
        p.kill()
        stdout, stderr = p.communicate()
        logging.exception(e)

        raise RuntimeError('Command timed out: {} \n{}\n{}'.format(
            p.returncode, stdout, stderr))
    else:
        if p.returncode != 0:

            HASH_SIZE_ERR = b'requires a 256 bit or larger hash (hash is SHA1)'
            if p.returncode == 2 and HASH_SIZE_ERR in stderr:
                pass

            else:
                raise SubprocessError(p.returncode, stdout, stderr)

    if stdout is None:
        raise RuntimeError('Got back empty stdout')

    if stderr is None:
        stderr = b''

    logging.debug(stdout.decode('utf-8'))
    logging.debug(stderr.decode('utf-8'))

    return stdout.decode('utf-8')


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    main(sys.argv[1:])
