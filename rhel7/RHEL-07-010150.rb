# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2016-01-14
# description: This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.
# impacts
title 'RHEL-07-010150 - When passwords are changed the number of repeating consecutive characters must not be more than four characters.'
control 'RHEL-07-010150' do
  impact 0.5
  title 'When passwords are changed the number of repeating consecutive characters must not be more than four characters.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.  Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  tag 'stig', 'RHEL-07-010150'
  tag severity: 'medium'
  tag checkid: 'C-RHEL-07-010150_chk'
  tag fixid: 'F-RHEL-07-010150_fix'
  tag version: 'RHEL-07-010150'
  tag ruleid: 'RHEL-07-010150_rule'
  tag fixtext: 'Configure the operating system to require the change of the number of repeating consecutive characters when passwords are changed by setting the “maxrepeat” option.

Add the following line to /etc/security/pwquality.conf conf (or modify the line to have the required value):

maxrepeat = 2'
  tag checktext: 'The "maxrepeat" option sets the maximum number of allowed same consecutive characters in a new password.

Check for the value of the “maxrepeat” option in /etc/security/pwquality.conf with the following command:

# grep maxrepeat /etc/security/pwquality.conf 
maxrepeat = 2

If the value of “maxrepeat” is set to more than 2, this is a finding.'

# START_DESCRIBE RHEL-07-010150
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE RHEL-07-010150

end

