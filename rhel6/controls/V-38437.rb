# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38437 - Automated file system mounting tools must not be enabled unless needed.'

control 'V-38437' do
  impact 0.1
  title 'Automated file system mounting tools must not be enabled unless needed.'
  desc '
All filesystems that are required for the successful operation of the system should be explicitly listed in "/etc/fstab" by an administrator. New filesystems should not be arbitrarily introduced via the automounter.

The "autofs" daemon mounts and unmounts filesystems, such as user home directories shared via NFS, on demand. In addition, autofs can be used to handle removable media, and the default configuration provides the cdrom device as "/misc/cd". However, this method of providing access to removable media is not common, so autofs can almost always be disabled if NFS is not in use. Even if NFS is required, it is almost always possible to configure filesystem mounts statically by editing "/etc/fstab" rather than relying on the automounter.
'
  tag 'stig','V-38437'
  tag severity: 'low'
  tag checkid: 'C-45991r1_chk'
  tag fixid: 'F-43381r1_fix'
  tag version: 'RHEL-06-000526'
  tag ruleid: 'SV-50237r1_rule'
  tag fixtext: '
If the "autofs" service is not needed to dynamically mount NFS filesystems or removable media, disable the service for all runlevels:

# chkconfig --level 0123456 autofs off

Stop the service if it is already running:

# service autofs stop
'
  tag checktext: '
To verify the "autofs" service is disabled, run the following command:

chkconfig --list autofs

If properly configured, the output should be the following:

autofs 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Verify the "autofs" service is not running:

# service autofs status

If the autofs service is enabled or running, this is a finding.
'

# START_CHECKS
  describe service('autofs') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
# END_CHECKS
end
