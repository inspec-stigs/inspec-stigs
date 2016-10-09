# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38630 - The graphical desktop environment must automatically lock after 15 minutes of inactivity and the system must require user reauthentication to unlock the environment.'

control 'V-38630' do
  impact 0.5
  title 'The graphical desktop environment must automatically lock after 15 minutes of inactivity and the system must require user reauthentication to unlock the environment.'
  desc '
Enabling idle activation of the screen saver ensures the screensaver will be activated after the idle delay. Applications requiring continuous, real-time screen display (such as network management products) require the login session does not have administrator rights and the display station is located in a controlled-access area.
'
  tag 'stig','V-38630'
  tag severity: 'medium'
  tag checkid: 'C-46189r3_chk'
  tag fixid: 'F-43579r1_fix'
  tag version: 'RHEL-06-000258'
  tag ruleid: 'SV-50431r3_rule'
  tag fixtext: '
Run the following command to activate the screensaver in the GNOME desktop after a period of inactivity:

# gconftool-2 --direct \
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
--type bool \
--set /apps/gnome-screensaver/idle_activation_enabled true
'
  tag checktext: '
If the GConf2 package is not installed, this is not applicable.

To check the screensaver mandatory use status, run the following command:

$ gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/idle_activation_enabled

If properly configured, the output should be "true".

If it is not, this is a finding.
'

# START_DESCRIBE V-38630
  tag 'gconf','GConf2','screensaver','idle'
  only_if { package('GConf2').installed? }
  describe command('gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/idle_activation_enabled') do
    its('stdout') { should match "true" }
  end
# END_DESCRIBE V-38630

end
