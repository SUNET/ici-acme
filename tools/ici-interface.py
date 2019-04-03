#!/usr/bin/env python3
#
# Copyright 2019 SUNET. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
#    1. Redistributions of source code must retain the above copyright notice, this list of
#       conditions and the following disclaimer.
#
#    2. Redistributions in binary form must reproduce the above copyright notice, this list
#       of conditions and the following disclaimer in the documentation and/or other materials
#       provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY SUNET ``AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
# FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL SUNET OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# The views and conclusions contained in the software and documentation are those of the
# authors and should not be interpreted as representing official policies, either expressed
# or implied, of SUNET.
#
# Author : Fredrik Thulin <fredrik@thulin.net>
#
"""
Monitor the ici-acme store for CSRs and pass them to the ICI CA. Monitor results from ICI
and put the generated certificates back into the ici-acme store.
"""


import os
import sys
import time
import logging
import argparse

import logging.handlers
import inotify.adapters
import yaml
from inotify.constants import IN_MODIFY, IN_MOVED_TO


_defaults = {'syslog': True,
             'debug': False,
             'store_dir': os.path.join(os.getcwd(), 'data/certificate'),
             'ici_input_dir': '/var/lib/ici/example/requests/server',
             'ici_output_dir': '/var/lib/ici/example/out-certs',
             'timeout': 60,
             }


def parse_args(defaults):
    parser = argparse.ArgumentParser(description = 'ICI <-> ICI-ACME interface',
                                     add_help = True,
                                     formatter_class = argparse.ArgumentDefaultsHelpFormatter,
    )

    # Optional arguments
    parser.add_argument('--store_dir',
                        dest = 'store_dir',
                        metavar = 'DIR', type = str,
                        default = defaults['store_dir'],
                        help = 'ICI-ACME store directory to monitor',
    )
    parser.add_argument('--ici_input_dir',
                        dest = 'ici_input_dir',
                        metavar = 'DIR', type = str,
                        default = defaults['ici_input_dir'],
                        help = 'ICI-CA input directory (where to put CSRs)',
    )
    parser.add_argument('--ici_output_dir',
                        dest = 'ici_output_dir',
                        metavar = 'DIR', type = str,
                        default = defaults['ici_output_dir'],
                        help = 'ICI-CA output directory (where to get certificates)',
    )
    parser.add_argument('--timeout',
                        dest = 'timeout',
                        metavar = 'SECONDS', type = int,
                        default = defaults['timeout'],
                        help = 'Re-check files at least this often',
    )
    parser.add_argument('--debug',
                        dest = 'debug',
                        action = 'store_true', default = defaults['debug'],
                        help = 'Enable debug operation',
    )
    parser.add_argument('--syslog',
                        dest = 'syslog',
                        action = 'store_true', default = defaults['syslog'],
                        help = 'Enable syslog output',
    )
    args = parser.parse_args()
    return args


def init_logger(myname, args):
    # This is the root log level
    level = logging.INFO
    if args.debug:
        level = logging.DEBUG
    logging.basicConfig(level = level, stream = sys.stderr,
                        format='%(asctime)s: %(name)s: %(levelname)s %(message)s')
    logger = logging.getLogger(myname)
    # If stderr is not a TTY, change the log level of the StreamHandler (stream = sys.stderr above) to WARNING
    if not sys.stderr.isatty() and not args.debug:
        for this_h in logging.getLogger('').handlers:
            this_h.setLevel(logging.WARNING)
    if args.syslog:
        syslog_h = logging.handlers.SysLogHandler()
        formatter = logging.Formatter('%(name)s: %(levelname)s %(message)s')
        syslog_h.setFormatter(formatter)
        logger.addHandler(syslog_h)
    return logger


def main(args, logger):
    i = inotify.adapters.Inotify()

    # construct mask by or-ing constants
    i.add_watch(args.store_dir, mask=(IN_MOVED_TO))
    i.add_watch(args.ici_output_dir, mask=(IN_MODIFY))

    logger.info(f'Waiting for file system events under {args.store_dir} and {args.ici_output_dir}')

    ignore_store_events = {}

    for event in i.event_gen(yield_nones = True):
        if event is None:
            # Whenever there are no events for args.timeout seconds, we poll
            # the files to make sure we didn't miss anything
            # TODO: implement this
            continue

        (_header, type_names, path, filename) = event

        logger.debug(f'Received file system event: path={repr(path)} fn={repr(filename)}, types={repr(type_names)!r}')

        if path == args.store_dir and filename.endswith('.yaml'):
            if ignore_store_events.pop(filename, False):
                # The event was generated because this script modified the file
                continue
            store_fn = os.path.join(path, filename)
            with open(store_fn, 'r') as fd:
                data = yaml.safe_load(fd.read())
            if 'csr' in data and data.get('certificate') is None:
                logger.info(f'Processing CSR in file {store_fn}')
                cert_id = filename.split('.')[0]
                out_fn = os.path.join(args.ici_input_dir, cert_id + '.csr')
                with open(out_fn, 'w') as out:
                    out.write('-----BEGIN CERTIFICATE REQUEST-----\n' +
                              data['csr'] + '\n' +
                              '-----END CERTIFICATE REQUEST-----\n')
        elif path == args.ici_output_dir and filename.endswith('.pem'):
            cert_fn = os.path.join(path, filename)
            logger.info(f'Processing certificate in file {cert_fn}')
            with open(cert_fn, 'r') as fd:
                cert_data = fd.read()
            cert_id = filename.split('.')[0]
            store_fn = os.path.join(args.store_dir, cert_id + '.yaml')
            if not os.path.isfile(store_fn):
                logger.error(f'Could not find ici-acme store certificate: {store_fn}')
                continue

            with open(store_fn, 'r') as fd:
                data = yaml.safe_load(fd.read())

            if data.get('certificate') is not None:
                logger.error(f'There is already a certificate in file {store_fn}')

            data['certificate'] = cert_data

            ignore_store_events[filename] = True
            with open(store_fn, 'w') as fd:
                fd.write(yaml.safe_dump(data))
            logger.debug(f'Saved certificate in ici-acme store file {store_fn}')

    return False


if __name__ == '__main__':
    try:
        progname = os.path.basename(sys.argv[0])
        args = parse_args(_defaults)
        logger = init_logger(progname, args)
        res = main(args, logger)
        if res is True:
            sys.exit(0)
        if res is False:
            sys.exit(1)
        sys.exit(int(res))
    except KeyboardInterrupt:
        sys.exit(0)
