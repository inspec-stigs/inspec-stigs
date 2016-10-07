# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38574 - The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (system-auth).'

control 'V-38574' do
  impact 0.5
  title 'The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (system-auth).'
  desc '
Using a stronger hashing algorithm makes password cracking attacks more difficult.
'
  tag 'stig','V-38574'
  tag severity: 'medium'
  tag checkid: 'C-46132r3_chk'
  tag fixid: 'F-43522r2_fix'
  tag version: 'RHEL-06-000062'
  tag ruleid: 'SV-50375r2_rule'
  tag fixtext: '
In "/etc/pam.d/system-auth" and "/etc/pam.d/system-auth-ac", among potentially other files, the "password" section of the files control which PAM modules execute during a password change. Set the "pam_unix.so" module in the "password" section to include the argument "sha512", as shown below: 

password sufficient pam_unix.so sha512 [other arguments...]

This will help ensure when local users change their passwords, hashes for the new passwords will be generated using the SHA-512 algorithm. This is the default.

Note that any updates made to "/etc/pam.d/system-auth" will be overwritten by the "authconfig" program.  The "authconfig" program should not be used.
'
  tag checktext: '
Inspect the "password" section of "/etc/pam.d/system-auth", "/etc/pam.d/system-auth-ac", and other files in "/etc/pam.d" and ensure that the "pam_unix.so" module includes the argument "sha512".

$ grep password /etc/pam.d/* | grep pam_unix.so | grep sha512

If it does not, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
