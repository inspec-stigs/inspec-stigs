# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38446 - The mail system must forward all mail for root to one or more system administrators.'

control 'V-38446' do
  impact 0.5
  title 'The mail system must forward all mail for root to one or more system administrators.'
  desc '
A number of system services utilize email messages sent to the root user to notify system administrators of active or impending issues.  These messages must be forwarded to at least one monitored email address.
'
  tag 'stig','V-38446'
  tag severity: 'medium'
  tag checkid: 'C-46001r1_chk'
  tag fixid: 'F-43391r1_fix'
  tag version: 'RHEL-06-000521'
  tag ruleid: 'SV-50246r1_rule'
  tag fixtext: '
Set up an alias for root that forwards to a monitored email address:

# echo "root: <system.administrator>@mail.mil" >> /etc/aliases
# newaliases
'
  tag checktext: '
Find the list of alias maps used by the Postfix mail server:

# postconf alias_maps

Query the Postfix alias maps for an alias for "root":

# postmap -q root <alias_map>

If there are no aliases configured for root that forward to a monitored email address, this is a finding.
'

# START_DESCRIBE V-38446
  describe file('/etc/aliases') do
    its('content') { should match /^root:/ }
  end
# END_DESCRIBE V-38446

end
