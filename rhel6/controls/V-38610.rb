# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38610 - The SSH daemon must set a timeout count on idle sessions.'

control 'V-38610' do
  impact 0.1
  title 'The SSH daemon must set a timeout count on idle sessions.'
  desc '
This ensures a user login will be terminated as soon as the "ClientAliveCountMax" is reached.
'
  tag 'stig','V-38610'
  tag severity: 'low'
  tag checkid: 'C-46168r1_chk'
  tag fixid: 'F-43558r1_fix'
  tag version: 'RHEL-06-000231'
  tag ruleid: 'SV-50411r1_rule'
  tag fixtext: '
To ensure the SSH idle timeout occurs precisely when the "ClientAliveCountMax" is set, edit "/etc/ssh/sshd_config" as follows: 

ClientAliveCountMax 0
'
  tag checktext: '
To ensure the SSH idle timeout will occur when the "ClientAliveCountMax" is set, run the following command: 

# grep ClientAliveCountMax /etc/ssh/sshd_config

If properly configured, output should be: 

ClientAliveCountMax 0


If it is not, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
