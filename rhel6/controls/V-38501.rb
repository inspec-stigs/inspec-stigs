# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38501 - The system must disable accounts after excessive login failures within a 15-minute interval.'

control 'V-38501' do
  impact 0.5
  title 'The system must disable accounts after excessive login failures within a 15-minute interval.'
  desc '
Locking out user accounts after a number of incorrect attempts within a specific period of time prevents direct password guessing attacks.
'
  tag 'stig','V-38501'
  tag severity: 'medium'
  tag checkid: 'C-46058r2_chk'
  tag fixid: 'F-43448r6_fix'
  tag version: 'RHEL-06-000357'
  tag ruleid: 'SV-50302r4_rule'
  tag fixtext: '
Utilizing "pam_faillock.so", the "fail_interval" directive configures the system to lock out accounts after a number of incorrect logon attempts. Modify the content of both "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" as follows: 

Add the following line immediately before the "pam_unix.so" statement in the "AUTH" section: 

auth required pam_faillock.so preauth silent deny=3 unlock_time=604800 fail_interval=900

Add the following line immediately after the "pam_unix.so" statement in the "AUTH" section: 

auth [default=die] pam_faillock.so authfail deny=3 unlock_time=604800 fail_interval=900

Add the following line immediately before the "pam_unix.so" statement in the "ACCOUNT" section: 

account required pam_faillock.so

Note that any updates made to "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" may be overwritten by the "authconfig" program.  The "authconfig" program should not be used.
'
  tag checktext: '
To ensure the failed password attempt policy is configured correctly, run the following command:

$ grep pam_faillock /etc/pam.d/system-auth /etc/pam.d/password-auth

For each file, the output should show "fail_interval=<interval-in-seconds>" where "interval-in-seconds" is 900 (15 minutes) or greater. If the "fail_interval" parameter is not set, the default setting of 900 seconds is acceptable. If that is not the case, this is a finding. 
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
