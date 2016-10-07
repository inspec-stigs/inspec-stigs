# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38474 - The system must allow locking of graphical desktop sessions.'

control 'V-38474' do
  impact 0.1
  title 'The system must allow locking of graphical desktop sessions.'
  desc '
The ability to lock graphical desktop sessions manually allows users to easily secure their accounts should they need to depart from their workstations temporarily.
'
  tag 'stig','V-38474'
  tag severity: 'low'
  tag checkid: 'C-46030r2_chk'
  tag fixid: 'F-43420r1_fix'
  tag version: 'RHEL-06-000508'
  tag ruleid: 'SV-50274r2_rule'
  tag fixtext: '
Run the following command to set the Gnome desktop keybinding for locking the screen:

# gconftool-2
--direct \
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
--type string \
--set /apps/gnome_settings_daemon/keybindings/screensaver "<Control><Alt>l"

Another keyboard sequence may be substituted for "<Control><Alt>l", which is the default for the Gnome desktop.
'
  tag checktext: '
If the GConf2 package is not installed, this is not applicable.

Verify the keybindings for the Gnome screensaver:

# gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome_settings_daemon/keybindings/screensaver

If no output is visible, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
