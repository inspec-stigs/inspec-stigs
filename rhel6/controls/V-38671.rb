# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38671 - The sendmail package must be removed.'

control 'V-38671' do
  impact 0.5
  title 'The sendmail package must be removed.'
  desc '
The sendmail software was not developed with security in mind and its design prevents it from being effectively contained by SELinux. Postfix should be used instead.
'
  tag 'stig','V-38671'
  tag severity: 'medium'
  tag checkid: 'C-46231r1_chk'
  tag fixid: 'F-43620r1_fix'
  tag version: 'RHEL-06-000288'
  tag ruleid: 'SV-50472r1_rule'
  tag fixtext: '
Sendmail is not the default mail transfer agent and is not installed by default. The "sendmail" package can be removed with the following command: 

# yum erase sendmail
'
  tag checktext: '
Run the following command to determine if the "sendmail" package is installed: 

# rpm -q sendmail


If the package is installed, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
