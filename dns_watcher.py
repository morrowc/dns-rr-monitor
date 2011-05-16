#!/usr/bin/python
#
# Copyright 2011 Chris Morrow, All Rights Reserved.

"""One-line documentation for dns_watcher module.

A detailed description of dns_watcher.
"""

__author__ = 'morrowc+gcode@ops-netman.net (Chris Morrow)'

import hashlib
import os
import pickle
import re
import subprocess
import sys

from datetime import datetime
from email.mime.text import MIMEText
from optparse import OptionParser


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

  def LoadStore(self):
    """Load a store of previously resolved RR data.
    Returns:
      True if the config is loaded
    Raises:
      IOError, if the file is unreadable.
    """
    if os.path.exists(self.store_file):
      try:
        fd = open(self.store_file, 'r')
      except IOError:
        raise FileNotFound('The store file (%s) is not available.'
            % self.store_file)
      self.store = pickle.load(fd)
      fd.close()
      return True
    else:
     self.store = {}

  def DumpStore(self):
    """Write the store to disk.

    Returns:
      a boolean, true if the file is written, false otherwise.

    Raises:
      IOError, if we can't write to the file (store_file)
    """
    try:
      fd = open(self.store_file, 'w')
    except IOError:
      raise
    print 'Pickling the store to the fd'
    pickle.dump(self.store, fd)
    fd.close()
    return True

  def Query(self, rr):
    """Check to see if the current RR is in the file.

    Args:
      rr: a string, the RR to lookup.

    Returns:
      a boolean, if the RR is there: True, else False.
    """
    try:
      if self.store[rr]:
        return self.store[rr]
    except KeyError:
      return False

  def Update(self, rr, result):
    """Update the RR history file.

    Args:
      rr: a string, the rr which was looked up.
      result: a string, the sha224 hexdigest to store for this RR.

    Returns:
      a boolean, True if we store the data way successfully.
    """
    print 'Storing in ram: %s as %s' % (rr, result)
    self.store[rr] = result

  def Dump(self):
    """Simply return the content of the store."""
    return self.store


def RequestRR(rr, qt):
  """Request an RR, return the resulting result.

  Args:
    rr: a string, the DNS RR to lookup.
    qt: a string, the DNS QueryType to use in the lookup. (ie: A, TXT, MX)

  Returns:
    a string, that is the resulting lookup sha224 hexdigested.
  """
  cmd = 'dig +short %s %s' % (qt, rr)
  fd = subprocess.Popen(cmd, shell=True,
                        stdout=subprocess.PIPE).stdout

  try:
    result = fd.read()
  except IOError:
    return None

  fd.close()
  return hashlib.sha256(result).hexdigest()


def main():
  opts = OptionParser()

  opts.add_option('-r', '--rr', dest='rr', help='The DNS RR to monitor.')

  opts.add_option('-t', '--qtype', dest='qt',
                  default='TXT', help='The DNS QueryType.')

  opts.add_option('-s', '--store', dest='store',
                  default='/tmp/dns_rr_store',
                  help='A local store of the RRs being monitored, and their '
                       'state')

  opts.add_option('-e', '--email', dest='email',
                  help='Email address to deliver alerts to.')

  opts.add_option('-D', '--dump_store', dest='dump_store',
                  help='Dump the content of the DNS RR store')

  (options, args) = opts.parse_args()

  if options.dump_store and options.store:
    try:
      store = Store(options.store)
    except FileNotFound, e:
      print 'Failed to open the store file to dump its content: %s' % e
    print store.Dump()
    sys.exit(1)

  if not options.rr:
    print 'Please provide an RR to monitor.'
    sys.exit(1)

  # Load the store from disk.
  try:
    store = Store(options.store)
    store.LoadStore()
  except IOError, e:
    print 'Failed to open the data store(%s): %s' % (options.store, e)

  # Query for the requested data, and pull the store's content for this RR.
  live_rr = RequestRR(options.rr, options.qt)
  current_rr = store.Query(options.rr)

  if not current_rr:
    print 'No currently stored RR for %s, storing that now.' % options.rr
    store.Update(options.rr, live_rr)
    store.DumpStore()
    sys.exit(1)

  if current_rr != live_rr:
    print 'Alert! the RR changed.'
    print 'Save: %s\nLive:%s' % (current_rr, live_rr)
    print 'Need to update the Store now as well.'


if __name__ == '__main__':
  main()
