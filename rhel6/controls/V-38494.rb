# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38494 - The system must prevent the root account from logging in from serial consoles.'

control 'V-38494' do
  impact 0.1
  title 'The system must prevent the root account from logging in from serial consoles.'
  desc '
Preventing direct root login to serial port interfaces helps ensure accountability for actions taken on the systems using the root account.
'
  tag 'stig','V-38494'
  tag severity: 'low'
  tag checkid: 'C-46051r1_chk'
  tag fixid: 'F-43441r1_fix'
  tag version: 'RHEL-06-000028'
  tag ruleid: 'SV-50295r1_rule'
  tag fixtext: '
To restrict root logins on serial ports, ensure lines of this form do not appear in "/etc/securetty":

ttyS0
ttyS1

Note:  Serial port entries are not limited to those listed above.  Any lines starting with "ttyS" followed by numerals should be removed
'
  tag checktext: '
To check for serial port entries which permit root login, run the following command:

# grep \'^ttyS[0-9]\' /etc/securetty

If any output is returned, then root login over serial ports is permitted.
If root login over serial ports is permitted, this is a finding.
'

# START_DESCRIBE V-38494
  describe command("grep '^ttyS[0-9]' /etc/securetty") do
    its('stdout') { should eq "" }
  end
# END_DESCRIBE V-38494

end
