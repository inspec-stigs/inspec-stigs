# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38460 - The NFS server must not have the all_squash option enabled.'

control 'V-38460' do
  impact 0.1
  title 'The NFS server must not have the all_squash option enabled.'
  desc '
The "all_squash" option maps all client requests to a single anonymous uid/gid on the NFS server, negating the ability to track file access by user ID.
'
  tag 'stig','V-38460'
  tag severity: 'low'
  tag checkid: 'C-46016r1_chk'
  tag fixid: 'F-43405r1_fix'
  tag version: 'RHEL-06-000515'
  tag ruleid: 'SV-50260r1_rule'
  tag fixtext: '
Remove any instances of the "all_squash" option from the file "/etc/exports".  Restart the NFS daemon for the changes to take effect.

# service nfs restart
'
  tag checktext: '
If the NFS server is read-only, in support of unrestricted access to organizational content, this is not applicable.

The related "root_squash" option provides protection against remote administrator-level access to NFS server content.  Its use is not a finding.

To verify the "all_squash" option has been disabled, run the following command:

# grep all_squash /etc/exports


If there is output, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
