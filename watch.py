#!/usr/bin/env python3

import csv
import glob
import gzip
import logging
import io
import sys
import re
import tempfile
import subprocess

from os.path import dirname, join as pjoin

import backoff
import requests

from utcdatetime import utcdatetime

LOG_PATTERN = r'.*sks\[\d+\]: (?P<date>\d+-\d+-\d+) (?P<time>\d+:\d+:\d+) Adding hash (?P<hash>[A-F0-9]{32})\n$'  # noqa
KEYSERVER_URL = 'https://keyserver.paulfurley.com'
LOG_GLOB = '/var/log/syslog*'
CACHE_CSV = pjoin(dirname(__file__), 'hashes_processed.csv')


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

        print("Loaded {} hashes".format(len(self._hashes)))

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

    print('Opening {}'.format(log_files))

    hash_count, process_count, fail_count = (0, 0, 0)

    cache = HashCache(CACHE_CSV)

    for updated_at, hash_ in parse_log_files(log_files):
        hash_count += 1

        if hash_ not in cache:
            try:
                process_hash(updated_at, hash_)
            except Exception as e:
                logging.exception(e)  # TODO: make sure this is monitored
                fail_count += 1
            else:
                cache.add_hash(hash_, updated_at)
                process_count += 1

    message = 'Processed {} new hashes {} failed ({} hashes total)'.format(
        process_count, fail_count, hash_count)

    if fail_count > 0:
        raise RuntimeError(message)
    else:
        print(message)
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


def process_hash(updated_at, hash_):
    try:
        fingerprint = get_fingerprint_from_hash(hash_)
    except ValueError as e:
        logging.warn("couldn't get fingerprint for {}".format(hash_))
        logging.exception(e)

    else:
        print('Hash {} has fingerprint {}'.format(hash_, fingerprint))
        send_key_updated_message(fingerprint, updated_at)


@backoff.on_exception(backoff.expo,
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
                raise ValueError('Hash no longer exists in keyserver')
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
        except SubprocessError:
            logging.warning('GPG failed with: {}'.format(response.text))
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


def send_key_updated_message(fingerprint, updated_at):
    """
    Tell the API the given fingerprint was updated with the datetime.
    """

    # NOTE: Actually just prod the web service so it attempts to sync the key
    url = 'https://www.expirybot.com/key/0x{}/'.format(
        fingerprint.replace(' ', ''))

    logging.info('Prodding {}'.format(url))
    response = requests.get(url)
    response.raise_for_status()


class SubprocessError(RuntimeError):
    pass


def stdout_for_subprocess(cmd_parts):
    logging.info('Running {}'.format(' '.join(cmd_parts)))
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
        raise SubprocessError('Command timed out: {} \n{}\n{}'.format(
            p.returncode, stdout, stderr))
    else:
        if p.returncode != 0:
            raise SubprocessError(
                'failed with code {} stdout: {} stderr: {}'.format(
                    p.returncode, stdout, stderr
                )
            )

    if stdout is None:
        raise SubprocessError('Got back empty stdout')

    if stderr is None:
        stderr = b''

    logging.debug(stdout.decode('utf-8'))
    logging.debug(stderr.decode('utf-8'))

    return stdout.decode('utf-8')


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    main(sys.argv[1:])
