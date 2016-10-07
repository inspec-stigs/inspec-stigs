# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38475 - The system must require passwords to contain a minimum of 14 characters.'

control 'V-38475' do
  impact 0.5
  title 'The system must require passwords to contain a minimum of 14 characters.'
  desc '
Requiring a minimum password length makes password cracking attacks more difficult by ensuring a larger search space. However, any security benefit from an onerous requirement must be carefully weighed against usability problems, support costs, or counterproductive behavior that may result.

While it does not negate the password length requirement, it is preferable to migrate from a password-based authentication scheme to a stronger one based on PKI (public key infrastructure).
'
  tag 'stig','V-38475'
  tag severity: 'medium'
  tag checkid: 'C-46029r1_chk'
  tag fixid: 'F-43419r1_fix'
  tag version: 'RHEL-06-000050'
  tag ruleid: 'SV-50275r1_rule'
  tag fixtext: '
To specify password length requirements for new accounts, edit the file "/etc/login.defs" and add or correct the following lines: 

PASS_MIN_LEN 14



The DoD requirement is "14". If a program consults "/etc/login.defs" and also another PAM module (such as "pam_cracklib") during a password change operation, then the most restrictive must be satisfied.
'
  tag checktext: '
To check the minimum password length, run the command: 

$ grep PASS_MIN_LEN /etc/login.defs

The DoD requirement is "14". 
If it is not set to the required value, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
