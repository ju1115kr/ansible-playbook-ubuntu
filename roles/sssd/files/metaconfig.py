#!/usr/bin/env python
#
# Copyright 2013 eBay Inc.
#

import json
import os
import subprocess
import tempfile
import errno
import re
import shutil
import socket
import stat
from StringIO import StringIO
from contextlib import contextmanager
from urllib2 import Request, urlopen, URLError, HTTPError
from time import time, sleep
from glob import glob
import platform
import httplib
import datetime
import resource


class MountFailedError(Exception):
    pass


class ProcessExecutionError(IOError):
    MESSAGE_TMPL = ('%(description)s\n'
                    'Command: %(cmd)s\n'
                    'Exit code: %(exit_code)s\n'
                    'Reason: %(reason)s\n'
                    'Stdout: %(stdout)r\n'
                    'Stderr: %(stderr)r')
    def __init__(self, stdout=None, stderr=None, exit_code=None, cmd=None, description=None, reason=None):
        if not cmd:
            self.cmd = '-'
        else:
            self.cmd = cmd
        if not description:
            self.description = 'Unexpected error while running command.'
        else:
            self.description = description
        if not isinstance(exit_code, (long, int)):
            self.exit_code = '-'
        else:
            self.exit_code = exit_code
        if not stderr:
            self.stderr = ''
        else:
            self.stderr = stderr
        if not stdout:
            self.stdout = ''
        else:
            self.stdout = stdout
        if reason:
            self.reason = reason
        else:
            self.reason = '-'
        message = self.MESSAGE_TMPL % {
            'description': self.description,
            'cmd': self.cmd,
            'exit_code': self.exit_code,
            'stdout': self.stdout,
            'stderr': self.stderr,
            'reason': self.reason,
        }
        IOError.__init__(self, message)


def subp(args, raise_flag=True, debug=True, data=None, rcs=None, env=None, capture=True, shell=False, cwd=None):
    if debug:
        print "%s metaconfig running cmd: %s" % (datetime.datetime.now(),args)
    if rcs is None:
        rcs = [0]
    try:
        if not capture:
            stdout = None
            stderr = None
        else:
            stdout = subprocess.PIPE
            stderr = subprocess.PIPE
        stdin = subprocess.PIPE
        sp = subprocess.Popen(args, cwd=cwd, stdout=stdout, stderr=stderr, stdin=stdin, env=env, shell=shell)
        pout, perr = sp.communicate(data)
    except OSError as oe:
        if raise_flag:
            raise ProcessExecutionError(cmd=args, reason=oe)
    rc = sp.returncode
    if rc not in rcs:
        if raise_flag:
            raise ProcessExecutionError(stdout=pout, stderr=perr, exit_code=rc, cmd=args)
    if not pout and capture:
        pout = ''
    if not perr and capture:
        perr = ''
    return pout, perr


def subp_with_pipe(args, data=None, rcs=None, cwd=None):
    if rcs is None:
        rcs = [0]
    try:
        counter = 0
        procs = {}
        for arg in args:
            stdout = subprocess.PIPE
            stderr = subprocess.PIPE
            stdin = subprocess.PIPE
            if counter == 0:
                procs['proc' + str(counter)] = subprocess.Popen(arg, cwd=cwd, stdout=stdout, stderr=stderr, stdin=stdin)
            else:
                procs['proc' + str(counter)] = subprocess.Popen(arg, cwd=cwd, stdout=stdout, stderr=stderr,
                                                                stdin=procs['proc' + str(counter - 1)].stdout)
                procs['proc' + str(counter - 1)].stdout.close()
            lastarg = arg
            counter += 1
        pout, perr = procs['proc' + str(counter - 1)].communicate(data)
    except OSError as oe:
        raise ProcessExecutionError(cmd=lastarg, reason=oe)
    rc = procs['proc' + str(counter - 1)].returncode
    if rc not in rcs:
        raise ProcessExecutionError(stdout=pout, stderr=perr, exit_code=rc, cmd=lastarg)
    return pout, perr


def load_file(fname, read_cb=None, quiet=False):
    ofh = StringIO()
    try:
        with open(fname, 'rb') as ifh:
            pipe_in_out(ifh, ofh, chunk_cb=read_cb)
    except IOError as oe:
        if not quiet:
            raise
        if oe.errno != errno.ENOENT:
            raise
    content = ofh.getvalue()
    return content


def pipe_in_out(in_fh, out_fh, chunk_size=1024, chunk_cb=None):
    bytes_piped = 0
    while True:
        data = in_fh.read(chunk_size)
        if data == '':
            break
        else:
            out_fh.write(data)
            bytes_piped += len(data)
            if chunk_cb:
                chunk_cb(bytes_piped)
    out_fh.flush()
    return bytes_piped


def mounts():
    fsmounted = {}
    try:
        # Go through mounts to see what is already mounted
        mount_locs = load_file('/proc/mounts').splitlines()
        for mpline in mount_locs:
            # Format at: man fstab
            try:
                (dev, mp, fstype, opts, _freq, _passno) = mpline.split()
            except:
                continue
                # If the name of the mount point contains spaces these
            # can be escaped as '\040', so undo that..
            mp = mp.replace('\\040', ' ')
            fsmounted[dev] = {
                'fstype': fstype,
                'mountpoint': mp,
                'opts': opts,
            }
    except IOError as oe:
        print 'I/O error({0}): {1}'.format(oe.errno, oe.strerror)
    except OSError as oe:
        print 'Error ({0}): {1}'.format(oe.errno, oe.strerror)
    return fsmounted


@contextmanager
def unmounter(mount_point):
    try:
        yield mount_point
    finally:
        if mount_point:
            umount_cmd = ['umount', '-l', mount_point]
            subp(umount_cmd)


@contextmanager
def tempdir(**kwargs):
    tdir = tempfile.mkdtemp(**kwargs)
    try:
        yield tdir
    finally:
        shutil.rmtree(tdir)


def read_file(target):
    try:
        with open(target) as file_handle:
            content = file_handle.read()
    except IOError as ioe:
        print 'I/O error({0}): {1}'.format(ioe.errno, ioe.strerror)
    return str(content)


def write_file(target, content):
    print "%s metaconfig writing file: %s" % (datetime.datetime.now(),target)
    try:
        with open(target, 'w') as file_handle:
            file_handle.write(content)
    except IOError as ioe:
        print 'I/O error({0}): {1}'.format(ioe.errno, ioe.strerror)

def append_file(target, content):
    print "%s metaconfig modifying file: %s" % (datetime.datetime.now(),target)
    try:
        with open(target, 'a') as file_handle:
            file_handle.write(content)
    except IOError as ioe:
        print 'I/O error({0}): {1}'.format(ioe.errno, ioe.strerror)


def set_ulimit():
    """set ulimit for all users, a cronus requirement, added by xima"""
    user_limits = None
    limits_conf_file = '/etc/security/limits.conf'
    try:
        user_limits, hard_limits = resource.getrlimit(resource.RLIMIT_NOFILE)
        #user_limits = subp(['ulimit', '-n'])[0]
    except:
        pass
    if int(user_limits) < 65535:
        limits_conf_content = read_file(limits_conf_file)
        limits_conf_content += '\n*\tsoft\tnofile\t65535\n'
        limits_conf_content += '*\thard\tnofile\t100000\n'
        limits_conf_content += 'root\tsoft\tnofile\t65535\n'
        limits_conf_content += 'root\thard\tnofile\t100000\n'
        write_file(limits_conf_file, limits_conf_content)
    else:
        print "%s metaconfig: skip ulimit. soft: %s, hard: %s" % (datetime.datetime.now(),user_limits,hard_limits)


def is_systemd():
    try:
        subp(['which', 'systemctl'])
        return True
    except ProcessExecutionError:
        return False


def filter_list(itemlist, itm):
    # List comprehension function
    # Search through itemlist[] to find the filter regex, return a list of values
    return [m.group(1) for l in itemlist for m in (itm(l),) if m]


def is_process(itm):
    pnames = []
    pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]
    for pid in pids:
        pnames.append(open(os.path.join('/proc', pid, 'cmdline'), 'rb').read())
    return filter_list(pnames, itm)


def dns_hold(timeout, maxcount):
    """Sleep for value specified as timeout if no valid DNS returned. Retry for maxcount value on each name server."""
    ip_addr = None
    hostinfo = None
    goodresults = 0
    nameservers = re.findall('nameserver\s+(\d+\.\d+\.\d+\.\d+)', read_file(resolv_conf))
    if maxcount < 2:
        raise Exception('Maximum count less than acceptable value, minimum: 2, value: {0}'.format(maxcount))
    nscount = len(nameservers)
    if nscount > 0:
        print 'Resolv.conf contains {0} name servers.'.format(len(nameservers))
        counter = 1
    else:
        raise Exception('Resolv.conf contains no name servers.')
    for nameserver in nameservers:
        count = 1
        print ' Querying {0} of {1} name servers.'.format(counter, nscount)
        while count < maxcount:
            host_name = socket.gethostname()
            if host_name != 'localhost':
                try:
                    eth0_inet_info = subp(['ip', '-o', '-f', 'inet', 'addr', 'show', 'scope', 'global'])[0]
                    ip_addr = re.findall('(\d+\.\d+\.\d+\.\d+)/', eth0_inet_info)[0]
                except:
                    pass
                if type(ip_addr) is str and ip_addr.startswith('10'):
                    try:
                        lookup = subp(['host', ip_addr, nameserver])[0]
                        hostinfo = re.search('([\w\.-]+)\n$', lookup).group(1), nameserver
                    except:
                        pass
                    if type(hostinfo) is tuple and host_name in hostinfo[0]:
                        goodresults += 1
                        break
            if count != maxcount:
                print 'Reverse DNS response error, sleeping {0} seconds before retry. Attempts remaining: {1}'\
                    .format(timeout, maxcount - count)
                sleep(timeout)
            else:
                raise Exception('Retry exceeded waiting for proper response from name server {0}.'.format(nameserver))
            count += 1
        counter += 1
    if goodresults == nscount:
        #print '\nGood reverse results returned from all name servers.'
        print ' Checking for forward results.'
        count = 0
        lookup = ""
        while count < maxcount:
            try:
                lookup = subp(['host', host_name])[0].strip()
            except:
                pass
            if ip_addr in lookup:
                break
            if count != maxcount:
                print 'Forward DNS response error, sleeping {0} seconds before retry. Attempts remaining: {1}'\
                    .format(timeout, maxcount - count)
                sleep(timeout)
            else:
                raise Exception('Retry exceeded waiting for proper forward lookup response.')
            count += 1
        print '\nGood forward results returned.'
    else:
        raise Exception('The logic has escaped the matrix.')


def dns_hold_forward(timeout, maxcount):
    """Sleep for value specified as timeout if no valid DNS returned. Retry for maxcount value on each name server."""
    eth0_inet_info = subp(['ip', '-o', '-f', 'inet', 'addr', 'show', 'global', 'scope'])[0]
    ip_addr = re.findall('(\d+\.\d+\.\d+\.\d+)/', eth0_inet_info)[0]
    goodresults = 0
    nameservers = re.findall('nameserver\s+(\d+\.\d+\.\d+\.\d+)', read_file(resolv_conf))
    if maxcount < 2:
        raise Exception('Maximum count less than acceptable value, minimum: 2, value: {0}'.format(maxcount))
    nscount = len(nameservers)
    if nscount > 0:
        print 'Resolv.conf contains {0} name servers.'.format(len(nameservers))
        counter = 1
    else:
        raise Exception('Resolv.conf contains no name servers.')
    if fqdn:
        my_fqdn = fqdn
    else:
        my_fqdn = socket.getfqdn()
    for nameserver in nameservers:
        count = 1
        lookup = ""
        print ' Querying {0} of {1} name servers.'.format(counter, nscount)
        while count < maxcount:
            try:
                lookup = subp(['host', my_fqdn, nameserver])[0]
            except:
                pass
            if ip_addr in lookup:
                goodresults += 1
                break
            if count != maxcount:
                print 'DNS response error, sleeping {0} seconds before retry. Attempts remaining: {1}'\
                    .format(timeout, maxcount - count)
                sleep(timeout)
            else:
                raise Exception('Retry exceeded waiting for proper response from name server {0}.'.format(nameserver))
            count += 1
        counter += 1
    if goodresults == nscount:
        print "Good forward DNS returned from all dns resolvers."
    else:
        raise Exception('ERROR indicating dns propergation issues. eBay postinstall failed to finish installing cronus and tivoli due to DNS not ready.')

def add_policy_based_routing(nic, nic_count, eth_inet_addr, eth_inet_gateway_addr):
    table_name = nic
    num_associate_routingtable = str(nic_count)+' '+table_name+'\n'
    append_file('/etc/iproute2/rt_tables', num_associate_routingtable)
    default_gateway_routing = '/sbin/ip route add default via '+eth_inet_gateway_addr+' dev '+nic+' table '+table_name
    routing_rule = '/sbin/ip rule add from '+eth_inet_addr+' table '+table_name
    contents = default_gateway_routing+'\n'+routing_rule+'\n'
    append_file('/etc/rc.local', contents)
    subp(['sed', '-i', 's/exit/#exit/', '/etc/rc.local'])

# main
print "%s metaconfig: eBay postinstall started running." % datetime.datetime.now()
dist = platform.linux_distribution()
distro_name = dist[0].lower()
distro_ver = dist[1]
distro_code = dist[2].lower()
os_distro = distro_name + distro_ver
print "%s metaconfig: vm OS distro is: %s" % (datetime.datetime.now(),os_distro)

if re.findall('ubuntu', distro_name.lower()):
    distro = 'ubuntu'
elif re.findall('red hat', distro_name.lower()) or\
        re.findall('centos', distro_name.lower()):
    distro = 'redhat'
    distro_ver = re.split('\.', distro_ver)[0]
else:
    distro = 'unknown'

os_string = distro + distro_ver
print "%s metaconfig: my os string is: %s" % (datetime.datetime.now(),os_string)

dsfile = '/var/lib/cloud/instance/datasource'

if os.path.isfile(dsfile):
    datasource = read_file(dsfile)
else:
    raise Exception('Failed to find instance data file ' + dsfile)

if re.findall('OpenStack', datasource):
    dstype = 'OpenStack'
    try:
        req = Request('http://169.254.169.254/openstack/latest/meta_data.json')
        response = urlopen(req)
    except URLError, e:
        if hasattr(e, 'reason'):
            raise Exception('Failed to contact metadata service.\nReason: ' + str(e.reason))
        elif hasattr(e, 'code'):
            raise Exception('Metadata service returned an error.\nCode: ' + str(e.code))
    else:
        if response.code == 200:
            meta = json.loads(response.read())
elif re.findall('ConfigDrive', datasource):
    dstype = 'ConfigDrive'
    source = re.findall('source=(.*)\]', datasource)
    if not source:
        raise Exception("Datasource not found")
    source = source[0]
    mode=os.stat(source).st_mode
    if(stat.S_ISBLK(mode)):
        # block device
        device = source
        mounted = mounts()
        with tempdir() as tmpd:
            if device in mounted:
                mountpoint = mounted[device]['mountpoint']
                meta = json.loads(read_file(mountpoint + '/openstack/latest/meta_data.json'))
            else:
                try:
                    mountcmd = ['mount', '-o', 'ro,sync', device, tmpd]
                    (out, err) = subp(mountcmd)
                    umount = tmpd
                    mountpoint = tmpd
                    with unmounter(umount):
                        meta = json.loads(read_file(mountpoint + '/openstack/latest/meta_data.json'))
                except (IOError, OSError) as exc:
                    raise MountFailedError('Failed mounting {0} to {1} due to: {2}'.format(device, tmpd, exc))
    else:
        meta = json.loads(read_file(source + '/openstack/latest/meta_data.json'))
else:
    raise Exception('Unable to determine datasource type.')

# Resolv.conf requires domain name, search domains, and name servers
print "%s metaconfig: start generating resolv.conf" % datetime.datetime.now()
try:
    resolv_conf = '/etc/resolv.conf'
    if meta['meta']['ipprovision'] == 'static':
        try:
            if os.path.isdir('/etc/resolvconf/resolv.conf.d'):
                resolv_conf = '/etc/resolvconf/resolv.conf.d/base'
                resolvconfd = True
                print "%s metaconfig: resolvconf is detected, updating /etc/resolvconf/resolv.conf.d/base." % datetime.datetime.now()
            else:
                print "%s metaconfig: no resolvconf installed, updating /etc/resolv.conf directly." % datetime.datetime.now()
                resolvconfd = False
        except:
            print 'Exception encountered finding resolver configuration.'
        if all(i in meta['meta'] for i in ('domainname', 'searchdomains', 'nameservers')):
            resolv_domain = 'domain ' + meta['meta']['domainname'] + '\n'
            resolver_conf = resolv_domain

            resolv_search = 'search ' + meta['meta']['searchdomains'].replace('.,', ' ').rstrip('.') + '\n'
            resolver_conf += resolv_search
            try:
                for name_server in meta['meta']['nameservers'].split(','):
                    resolver_conf += 'nameserver ' + name_server + '\n'
                resolver_conf += 'options timeout:10 rotate ndots:2 retry:3\n'
            except:
                print 'Did not find multiple values for name servers, minimum 2 required.'

            write_file(resolv_conf, resolver_conf)
            if resolvconfd is True:
                subp(['resolvconf', '-u'])
    else:
        print 'Value for ipprovision is not "static" in metadata, assuming automatic resolver configuration.'
except:
    print 'IP provisioning method not specified, skipping resolver configuration.'

# update /etc/hosts
#fqdn = meta['meta']['fqdn']
fqdn = subp(['hostname'])[0].strip() + '.tkbell.gmarket.nh'
print "%s metaconfig: start updating /etc/hosts and /etc/mailname. my fqdn is %s" % (datetime.datetime.now(),fqdn)
if fqdn:
    try:
        # updating the mail name.
        mailname_file = '/etc/mailname'
        mailname_str = "%s\n" % fqdn
        write_file(mailname_file, mailname_str)
        # correct the hostname if its not set right.
        short_name = fqdn.split('.')[0]
        print "%s metaconfig: my short name is %s" % (datetime.datetime.now(),short_name)
        if os.path.exists("/etc/hostname"):
            if not re.findall(short_name, read_file('/etc/hostname')):
                subp(['hostnamectl', 'set-hostname', fqdn])
        # gather ip addr and then update /etc/hosts file.
        eth0_inet_info = subp(['ip', '-o', '-f', 'inet', 'addr', 'show', 'scope', 'global'])[0]
        eth0_inet_addr = re.findall('(\d+\.\d+\.\d+\.\d+)/', eth0_inet_info)[0]
        if eth0_inet_addr:
            print "%s metaconfig: my eth0 ip is: %s" % (datetime.datetime.now(),eth0_inet_addr)
            etc_hosts_string = "{0}\t{1}\t{2}\n".format(eth0_inet_addr, fqdn, short_name)
            etc_hosts_file = '/etc/hosts'
            write_file(etc_hosts_file, "127.0.0.1\tlocalhost\n")
            append_file(etc_hosts_file, etc_hosts_string)
        else:
            print 'Error: no ip found with eth0!'
    except:
        print 'Error: Not able to update /etc/hosts!'
else:
    print 'No fqdn detected in metadata.json, will not update /etc/hosts!'

# adding vm owner to access.conf and sudoers.
print "%s metaconfig: adding vm owner to access.conf and sudoers." % datetime.datetime.now()
if 'os_config_username' in meta['meta']:
    try:
        sssd_conf_mtime = os.stat('/etc/sssd/sssd.conf').st_mtime
    except:
        print 'Could not read mtime of /etc/sssd/sssd.conf, will not setup directory user.'
    else:
        conf_file = '/etc/security/access.conf'
        if os.path.isfile(conf_file):
            # Only modify access.conf if we're in an ldap enabled environment
            # Assume so by seeing if sssd.conf was modified in the last five minutes
            # Or if our CoS indicates we're in dev
            ####if int(time() - sssd_conf_mtime) <= 300 :
                access_conf = read_file(conf_file)

                if re.sub(re.compile(r'^#.*?\n', re.MULTILINE), '', access_conf) != '':
                    access_conf = re.sub(re.compile(r'(?<!^#)[+-].+?\n', re.MULTILINE), '', access_conf)

                if len(access_conf) >= 0:
                    access_conf += '\n'

                #if meta['meta']['project_cos'] != 'dev':
                #    access_conf += "+:@opers:ALL\n"
                #    access_conf += "+:@unixcore:ALL\n"
                #    access_conf += "+:@stratus-administrators:ALL\n"
                #    access_conf += "+:@stratus-infrastructure:ALL\n"
                #    access_conf += "+:@paas-administrators:ALL\n"
                access_conf += '+:ALL:LOCAL\n+:root:ALL\n'
                # For now, stack user and vm owner access is still needed by montage and many other prod use cases.
                # We need to keep both of them for now, and later if we decide to disable them in prod, we will.
                access_conf += '+:tkbell:ALL\n'
                access_conf += '+:cpmadm:ALL\n'
                access_conf += '+:{0}:ALL\n'.format(meta['meta']['os_config_username'])
                access_conf += '-:ALL:ALL\n'
                write_file(conf_file, access_conf)

                sudoers_conf_file = '/etc/sudoers.d/ldapuser'
                sudoer = '{0} ALL=(ALL) ALL\n'.format(meta['meta']['os_config_username'])
                write_file(sudoers_conf_file, sudoer)
                os.chmod(sudoers_conf_file, 0440)
            ###else:
            ###    print 'CoS not ldap enabled based on sssd.conf mtime > 5 minutes ago.'
        else:
            print conf_file + ' not found, user account restriction not active.'
else:
    print 'Value for os_config_username not specified in metadata, directory user not configured.'

# update packages
if distro == 'redhat':
    try:
        subp(['yum', '-y', 'update'])
    except:
        pass
elif distro == 'ubuntu':
    try:
        subp(['apt-get', '-y', 'update'])
    except:
        pass

# install nginx, apache
if 'pkg_nginx' in meta['meta']:
    if distro == 'redhat':
        try:
            subp(['yum', '-y', 'install', 'nginx'])
        except:
            pass
    if distro == 'ubuntu':
        try:
            subp(['apt-get', '-y', 'install', 'nginx'])
        except:
            pass

if 'pkg_apache' in meta['meta']:
    if distro == 'redhat':
        try:
            subp(['yum', '-y', 'install', 'httpd'])
        except:
            pass
    if distro == 'ubuntu':
        try:
            subp(['apt-get', '-y', 'install', 'apache2'])
        except:
            pass

# create symbol link to make /export/home and /home combined
if not os.path.exists('/export/home'):
    if not os.path.exists('/export'):
        os.mkdir('/export')
    os.symlink('/home', '/export/home')

valid_trues = ['1', 'true']

# CLDINFRA-12419 comment "Defaults    requiretty" in /etc/sudoers
sudoers_contents = read_file('/etc/sudoers')
if re.findall('Defaults    requiretty', sudoers_contents):
    subp(['sed', '-i', 's/Defaults    requiretty/#Defaults    requiretty/', '/etc/sudoers'])

if distro == 'redhat':
    contents = read_file('/etc/sysconfig/network')
    try:
        hostname = fqdn
    except Exception:
        print 'Problem encountered while looking up instance hostname.'
    if re.findall('HOSTNAME=', contents):
        contents = re.sub('HOSTNAME=.*\n', 'HOSTNAME={0}\n'.format(hostname), contents)
    else:
        contents += 'HOSTNAME={0}\n'.format(hostname)
    write_file('/etc/sysconfig/network', contents)
    if is_systemd():
        subp(['authconfig', '--enablesssd', '--update'], raise_flag=False)

print "%s metaconfig: finished all eBay postinstall tasks.\n" % datetime.datetime.now()
