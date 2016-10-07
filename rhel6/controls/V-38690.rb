# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38690 - Emergency accounts must be provisioned with an expiration date.
'

control 'V-38690' do
  impact 0.1
  title 'Emergency accounts must be provisioned with an expiration date.
'
  desc '
When emergency accounts are created, there is a risk they may remain in place and active after the need for them no longer exists. Account expiration greatly reduces the risk of accounts being misused or hijacked.
'
  tag 'stig','V-38690'
  tag severity: 'low'
  tag checkid: 'C-46251r1_chk'
  tag fixid: 'F-43639r1_fix'
  tag version: 'RHEL-06-000298'
  tag ruleid: 'SV-50491r1_rule'
  tag fixtext: '
In the event emergency accounts are required, configure the system to terminate them after a documented time period. For every emergency account, run the following command to set an expiration date on it, substituting "[USER]" and "[YYYY-MM-DD]" appropriately: 

# chage -E [YYYY-MM-DD] [USER]

"[YYYY-MM-DD]" indicates the documented expiration date for the account.
'
  tag checktext: '
For every emergency account, run the following command to obtain its account aging and expiration information: 

# chage -l [USER]

Verify each of these accounts has an expiration date set as documented. 
If any emergency accounts have no expiration date set or do not expire within a documented time frame, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
