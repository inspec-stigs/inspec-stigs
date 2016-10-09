# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38692 - Accounts must be locked upon 35 days of inactivity.'

control 'V-38692' do
  impact 0.1
  title 'Accounts must be locked upon 35 days of inactivity.'
  desc '
Disabling inactive accounts ensures that accounts which may not have been responsibly removed are not available to attackers who may have compromised their credentials.
'
  tag 'stig','V-38692'
  tag severity: 'low'
  tag checkid: 'C-46254r2_chk'
  tag fixid: 'F-43641r2_fix'
  tag version: 'RHEL-06-000334'
  tag ruleid: 'SV-50493r1_rule'
  tag fixtext: '
To specify the number of days after a password expires (which signifies inactivity) until an account is permanently disabled, add or correct the following lines in "/etc/default/useradd", substituting "[NUM_DAYS]" appropriately:

INACTIVE=[NUM_DAYS]

A value of 35 is recommended. If a password is currently on the verge of expiration, then 35 days remain until the account is automatically disabled. However, if the password will not expire for another 60 days, then 95 days could elapse until the account would be automatically disabled. See the "useradd" man page for more information. Determining the inactivity timeout must be done with careful consideration of the length of a "normal" period of inactivity for users in the particular environment. Setting the timeout too low incurs support costs and also has the potential to impact availability of the system to legitimate users.
'
  tag checktext: '
To verify the "INACTIVE" setting, run the following command:

grep "INACTIVE" /etc/default/useradd

The output should indicate the "INACTIVE" configuration option is set to an appropriate integer as shown in the example below:

# grep "INACTIVE" /etc/default/useradd
INACTIVE=35

If it does not, this is a finding.
'

# START_DESCRIBE V-38692
  tag 'password','user','inactive'
  describe parse_config_file('/etc/default/useradd') do
    its('INACTIVE') { should cmp '35' }
  end
# END_DESCRIBE V-38692

end
