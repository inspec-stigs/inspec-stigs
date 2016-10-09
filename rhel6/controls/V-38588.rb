# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38588 - The system must not permit interactive boot.'

control 'V-38588' do
  impact 0.5
  title 'The system must not permit interactive boot.'
  desc '
Using interactive boot, the console user could disable auditing, firewalls, or other services, weakening system security.
'
  tag 'stig','V-38588'
  tag severity: 'medium'
  tag checkid: 'C-46146r1_chk'
  tag fixid: 'F-43536r1_fix'
  tag version: 'RHEL-06-000070'
  tag ruleid: 'SV-50389r1_rule'
  tag fixtext: '
To disable the ability for users to perform interactive startups, edit the file "/etc/sysconfig/init". Add or correct the line:

PROMPT=no

The "PROMPT" option allows the console user to perform an interactive system startup, in which it is possible to select the set of services which are started on boot.
'
  tag checktext: '
To check whether interactive boot is disabled, run the following command:

$ grep PROMPT /etc/sysconfig/init

If interactive boot is disabled, the output will show:

PROMPT=no


If it does not, this is a finding.
'

# START_DESCRIBE V-38588
  describe parse_config_file('/etc/sysconfig/init') do
   its('PROMPT') { should eq 'no' }
  end
# END_DESCRIBE V-38588

end
