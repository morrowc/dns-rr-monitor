#!/usr/bin/python
#
# Copyright 2011 Chris Morrow, All Rights Reserved.

"""One-line documentation for dns_watcher module.

A detailed description of dns_watcher.
"""

__author__ = 'morrowc+gcode@ops-netman.net (Chris Morrow)'

import hashlib
import logging
import os
import pickle
import smtplib
import subprocess
import sys

from datetime import datetime
from email.mime.text import MIMEText
from optparse import OptionParser

LOG = '/tmp/dns_rr_monitor.log'
MAILHOST = 'mail'


class Error(Exception):
  """Base Error class for Storage class."""


class FileNotFound(Error):
  """The store file isn't found."""


class Store(object):
  """A file store for all RR data, a history."""

  def __init__(self, store_file):
    self.store_file = store_file
    self.dtg = datetime.now().strftime('%Y-%m-%d')
    self.store = {}

  def loadStore(self):
    """Load a store of previously resolved RR data.
    Returns:
      True if the config is loaded
    Raises:
      IOError, if the file is unreadable.
    """
    logging.debug('Loading the store from disk.')
    if os.path.exists(self.store_file):
      try:
        fd = open(self.store_file, 'r')
      except IOError:
        logging.debug('The store file (%s) is not available for reading.',
            self.store_file)
        raise FileNotFound('The store file (%s) is not available.'
            % self.store_file)
      logging.debug('Pickling the store off disk and into ram.')
      self.store = pickle.load(fd)
      fd.close()
      return True
    else:
      self.store = {}

  def dumpStore(self):
    """Write the store to disk.

    Returns:
      a boolean, true if the file is written, false otherwise.

    Raises:
      IOError, if we can't write to the file (store_file)
    """
    logging.debug('Writing the store back to disk in pickle-form.')
    try:
      fd = open(self.store_file, 'w')
    except IOError:
      logging.debug('Oops, writing the store failed.')
      raise
    logging.debug('Pickling the store to the fd(%s)', self.store_file)
    pickle.dump(self.store, fd)
    fd.close()
    return True

  def query(self, rr):
    """Check to see if the current RR is in the file.

    Args:
      rr: a string, the RR to lookup.

    Returns:
      a boolean, if the RR is there: True, else False.
    """
    logging.debug('Querying the store for %s', rr)
    try:
      if self.store[rr]:
        return self.store[rr]
    except KeyError:
      return False

  def update(self, rr, result):
    """Update the RR history file.

    Args:
      rr: a string, the rr which was looked up.
      result: a string, the sha224 hexdigest to store for this RR.

    Returns:
      a boolean, True if we store the data way successfully.
    """
    logging.debug('Storing in ram: %s as %s', rr, result)
    self.store[rr] = result

  def dump(self):
    """Simply return the content of the store."""
    logging.debug('Dumping the store database.')
    return self.store


def requestRR(rr, qt, hash=True):
  """Request an RR, return the resulting result.

  Args:
    rr: a string, the DNS RR to lookup.
    qt: a string, the DNS QueryType to use in the lookup. (ie: A, TXT, MX)
    hash: a boolean, if True return a hash, else return the text of the RR.

  Returns:
    a string, that is the resulting lookup sha224 hexdigested.
  """
  cmd = 'dig +short %s %s' % (qt, rr)
  logging.debug('Looking up the RR (%s) and QType (%s) with cmd: %s',
      rr, qt, cmd)
  fd = subprocess.Popen(cmd, shell=True,
                        stdout=subprocess.PIPE).stdout

  try:
    result = fd.read()
  except IOError:
    return None

  fd.close()
  logging.debug('Lookup was successful: %s', result)
  if hash:
    logging.debug('Returning a hashed/storable version of the result.')
    return hashlib.sha256(result).hexdigest()
  else:
    logging.debug('Returning the plain-text version of the result.')
    return result


def sendAlert(fromaddr, rr, email, result):
  """Send an alert email to the designated destination.

  Args:
    fromaddr: a string, the From address to use in the email creation.
    rr: a string, the DNS RR being tracked.
    email: a string, the destination to email the alert.
    resutl: a string, the resolved RR.

  Returns:
    a Boolean, True if email is delivered, False otherwise.
  """
  msg = MIMEText('The RR (%s) changed content, new: %s' %(rr, result ))
  msg['Subject'] = 'DNS-RR-Monitoer Alert: %s changed.' % rr
  msg['From'] = fromaddr
  msg['To'] = email

  try:
    smtp = smtplib.SMTP(MAILHOST)
    smtp.sendmail(fromaddr, [email], msg.as_string())
    smtp.quit()
  except smtplib.SMTPConnectError, err:
    logging.debug('Failed to connect to %s and deliver email: %s',
        MAILHOST, err)
    return False
  except smtplib.SMTPHeloError, err:
    logging.debug('The server didnt like our helo: %s', err)
    return False
  except smtplib.SMTPDataError, err:
    logging.debug('Sending of the email failed: %s', err)
    return False
  except smtplib.SMTPException, err:
    logging.debug('Email send faild, SMTP Exception: %s', err)
    return False

  logging.debug('Sending of the email was successful.')
  return True


def main():
  """The main/starting function for this script."""
  opts = OptionParser()

  opts.add_option('-D', '--dump_store', dest='dump_store',
                  help='Dump the content of the DNS RR store')

  opts.add_option('-e', '--email', dest='email',
                  help='Email address to deliver alerts to.')

  opts.add_option('-f', '--from', dest='fromaddr',
                  default=os.environ['USER'],
                  help='An address to send this alert From.')

  opts.add_option('-l', '--log', dest='log',
                  default=LOG,
                  help='The destination file in which to log results.')

  opts.add_option('-m', '--mailhost', dest='mailhost',
                  default=MAILHOST,
                  help='The mailhost through which to attempt mail delivery.')

  opts.add_option('-r', '--rr', dest='rr', help='The DNS RR to monitor.')

  opts.add_option('-s', '--store', dest='store',
                  default='/tmp/dns_rr_store',
                  help='A local store of the RRs being monitored, and their '
                       'state')

  opts.add_option('-t', '--qtype', dest='qt',
                  default='TXT', help='The DNS QueryType.')

  (options, args) = opts.parse_args()

  logging.basicConfig(filename=options.log, level=logging.DEBUG)

  logging.debug('Starting up, checking for basic/required args.')
  logging.debug('Args passed in: %s', args)
  logging.debug('Options passed in: %s', options)
  if options.dump_store and options.store:
    try:
      store = Store(options.store)
    except FileNotFound, err:
      logging.debug('Failed to open the store file to dump its content: %s',
          err)
    logging.debug('Store Content:\n%s', store.dump())
    print store.dump()
    logging.debug('exiting cleanly, after store dump.')
    sys.exit(1)

  if not options.rr:
    logging.debug('No RR was provided to monitor, exiting uncleanly.')
    print 'Please provide an RR to monitor.'
    sys.exit(1)

  # Load the store from disk.
  try:
    store = Store(options.store)
    store.loadStore()
  except IOError, err:
    logging.debug('Failed to open the data store(%s): %s', options.store,
        err)
    print 'Failed to open the data store(%s): %s' % (options.store, err)

  # Query for the requested data, and pull the store's content for this RR.
  live_rr = requestRR(options.rr, options.qt)
  current_rr = store.query(options.rr)
  logging.debug('Current store content for %s:\n\t%s', options.rr, current_rr)
  logging.debug('New RR content:\n\t%s', live_rr)

  if not current_rr:
    logging.debug('No currently stored RR for %s, storing the current result.',
        options.rr)
    store.update(options.rr, live_rr)
    store.dumpStore()
    logging.debug('Exiting after storing a first-time lookup.')
    sys.exit(1)

  if current_rr != live_rr:
    logging.debug('Changes to the RR happened, sending an alert email.')
    if not (sendAlert(options.fromaddr, options.rr, options.email,
        requestRR(options.rr, options.qt, False))):
      logging.debug('Alert! the RR changed.')
      logging.debug('Save:\n\t%s\nLive:\n\t%s', current_rr, live_rr)
      logging.debug('Resulting RR: %s', requestRR(options.rr,
                                                  options.qt,
                                                  False))
      logging.debug('Sending of email failed.')
    else:
      logging.debug('Successfully sent email, storing the changed RR data.')
      store.update(options.rr, live_rr)
      store.dumpStore()
  else:
    logging.debug('No change in RR')


if __name__ == '__main__':
  main()
