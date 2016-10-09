# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38652 - Remote file systems must be mounted with the nodev option.'

control 'V-38652' do
  impact 0.5
  title 'Remote file systems must be mounted with the nodev option.'
  desc '
Legitimate device files should only exist in the /dev directory. NFS mounts should not present device files to users.
'
  tag 'stig','V-38652'
  tag severity: 'medium'
  tag checkid: 'C-46212r2_chk'
  tag fixid: 'F-43601r1_fix'
  tag version: 'RHEL-06-000269'
  tag ruleid: 'SV-50453r2_rule'
  tag fixtext: '
Add the "nodev" option to the fourth column of "/etc/fstab" for the line which controls mounting of any NFS mounts.
'
  tag checktext: '
To verify the "nodev" option is configured for all NFS mounts, run the following command:

$ mount | grep "nfs "

All NFS mounts should show the "nodev" setting in parentheses, along with other mount options.
If the setting does not show, this is a finding.
'

# START_DESCRIBE V-38652
  tag 'mount','fstab','nfs'
  describe command("mount | grep 'nfs ' | grep -v 'nodev'") do
    its('stdout') { should eq "" }
  end
# END_DESCRIBE V-38652

end
