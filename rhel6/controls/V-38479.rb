# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38479 - User passwords must be changed at least every 60 days.'

control 'V-38479' do
  impact 0.5
  title 'User passwords must be changed at least every 60 days.'
  desc '
Setting the password maximum age ensures users are required to periodically change their passwords. This could possibly decrease the utility of a stolen password. Requiring shorter password lifetimes increases the risk of users writing down the password in a convenient location subject to physical compromise.
'
  tag 'stig','V-38479','password'
  tag severity: 'medium'
  tag checkid: 'C-46034r1_chk'
  tag fixid: 'F-43424r1_fix'
  tag version: 'RHEL-06-000053'
  tag ruleid: 'SV-50279r1_rule'
  tag fixtext: '
To specify password maximum age for new accounts, edit the file "/etc/login.defs" and add or correct the following line, replacing [DAYS] appropriately:

PASS_MAX_DAYS [DAYS]

The DoD requirement is 60.
'
  tag checktext: '
To check the maximum password age, run the command:

$ grep PASS_MAX_DAYS /etc/login.defs

The DoD requirement is 60.
If it is not set to the required value, this is a finding.
'

# START_DESCRIBE V-38479
  describe login_defs do
    its('PASS_MAX_DAYS') { should eq '60' }
  end
# END_DESCRIBE V-38479

end
