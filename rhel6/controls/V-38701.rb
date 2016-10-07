# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38701 - The TFTP daemon must operate in secure mode which provides access only to a single directory on the host file system.'

control 'V-38701' do
  impact 1.0
  title 'The TFTP daemon must operate in secure mode which provides access only to a single directory on the host file system.'
  desc '
Using the "-s" option causes the TFTP service to only serve files from the given directory. Serving files from an intentionally specified directory reduces the risk of sharing files which should remain private.
'
  tag 'stig','V-38701'
  tag severity: 'high'
  tag checkid: 'C-46263r1_chk'
  tag fixid: 'F-43650r1_fix'
  tag version: 'RHEL-06-000338'
  tag ruleid: 'SV-50502r1_rule'
  tag fixtext: '
If running the "tftp" service is necessary, it should be configured to change its root directory at startup. To do so, ensure "/etc/xinetd.d/tftp" includes "-s" as a command line argument, as shown in the following example (which is also the default): 

server_args = -s /var/lib/tftpboot
'
  tag checktext: '
Verify "tftp" is configured by with the "-s" option by running the following command: 

grep "server_args" /etc/xinetd.d/tftp

The output should indicate the "server_args" variable is configured with the "-s" flag, matching the example below:

# grep "server_args" /etc/xinetd.d/tftp
server_args = -s /var/lib/tftpboot

If it does not, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
