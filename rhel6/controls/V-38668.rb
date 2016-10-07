# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38668 - The x86 Ctrl-Alt-Delete key sequence must be disabled.'

control 'V-38668' do
  impact 1.0
  title 'The x86 Ctrl-Alt-Delete key sequence must be disabled.'
  desc '
A locally logged-in user who presses Ctrl-Alt-Delete, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot. In the GNOME graphical environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken.
'
  tag 'stig','V-38668'
  tag severity: 'high'
  tag checkid: 'C-46228r2_chk'
  tag fixid: 'F-43617r2_fix'
  tag version: 'RHEL-06-000286'
  tag ruleid: 'SV-50469r2_rule'
  tag fixtext: '
By default, the system includes the following line in "/etc/init/control-alt-delete.conf" to reboot the system when the Ctrl-Alt-Delete key sequence is pressed:

exec /sbin/shutdown -r now "Ctrl-Alt-Delete pressed"


To configure the system to log a message instead of rebooting the system, add the following line to "/etc/init/control-alt-delete.override" to read as follows:

exec /usr/bin/logger -p security.info "Ctrl-Alt-Delete pressed"
'
  tag checktext: '
To ensure the system is configured to log a message instead of rebooting the system when Ctrl-Alt-Delete is pressed, ensure the following line is in "/etc/init/control-alt-delete.override":

exec /usr/bin/logger -p security.info "Control-Alt-Delete pressed"

If the system is not configured to block the shutdown command when Ctrl-Alt-Delete is pressed, this is a finding. 
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
