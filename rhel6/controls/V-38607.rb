# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38607 - The SSH daemon must be configured to use only the SSHv2 protocol.'

control 'V-38607' do
  impact 1.0
  title 'The SSH daemon must be configured to use only the SSHv2 protocol.'
  desc '
SSH protocol version 1 suffers from design flaws that result in security vulnerabilities and should not be used.
'
  tag 'stig','V-38607'
  tag severity: 'high'
  tag checkid: 'C-46165r1_chk'
  tag fixid: 'F-43555r1_fix'
  tag version: 'RHEL-06-000227'
  tag ruleid: 'SV-50408r1_rule'
  tag fixtext: '
Only SSH protocol version 2 connections should be permitted. The default setting in "/etc/ssh/sshd_config" is correct, and can be verified by ensuring that the following line appears:

Protocol 2
'
  tag checktext: '
To check which SSH protocol version is allowed, run the following command:

# grep Protocol /etc/ssh/sshd_config

If configured properly, output should be

Protocol 2


If it is not, this is a finding.
'

# START_DESCRIBE V-38607
  tag 'sshd','SSHv2'
  describe sshd_config do
    its('Protocol') { should eq '2' }
  end

# END_DESCRIBE V-38607

end
