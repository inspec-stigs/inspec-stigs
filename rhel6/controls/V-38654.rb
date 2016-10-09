# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38654 - Remote file systems must be mounted with the nosuid option.'

control 'V-38654' do
  impact 0.5
  title 'Remote file systems must be mounted with the nosuid option.'
  desc '
NFS mounts should not present suid binaries to users. Only vendor-supplied suid executables should be installed to their default location on the local filesystem.
'
  tag 'stig','V-38654'
  tag severity: 'medium'
  tag checkid: 'C-46214r3_chk'
  tag fixid: 'F-43603r1_fix'
  tag version: 'RHEL-06-000270'
  tag ruleid: 'SV-50455r2_rule'
  tag fixtext: '
Add the "nosuid" option to the fourth column of "/etc/fstab" for the line which controls mounting of any NFS mounts.
'
  tag checktext: '
To verify the "nosuid" option is configured for all NFS mounts, run the following command:

$ mount | grep nfs

All NFS mounts should show the "nosuid" setting in parentheses, along with other mount options.
If the setting does not show, this is a finding.
'

# START_DESCRIBE V-38654
  tag 'mount','fstab','nfs','nosuid'
  describe command("mount | grep 'nfs ' | grep -v 'nosuid'") do
    its('stdout') { should eq "" }
  end
# END_DESCRIBE V-38654

end
