# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38638 - The graphical desktop environment must have automatic lock enabled.'

control 'V-38638' do
  impact 0.5
  title 'The graphical desktop environment must have automatic lock enabled.'
  desc '
Enabling the activation of the screen lock after an idle period ensures password entry will be required in order to access the system, preventing access by passersby.
'
  tag 'stig','V-38638'
  tag severity: 'medium'
  tag checkid: 'C-46198r3_chk'
  tag fixid: 'F-43587r1_fix'
  tag version: 'RHEL-06-000259'
  tag ruleid: 'SV-50439r3_rule'
  tag fixtext: '
Run the following command to activate locking of the screensaver in the GNOME desktop when it is activated:

# gconftool-2 --direct \
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
--type bool \
--set /apps/gnome-screensaver/lock_enabled true
'
  tag checktext: '
If the GConf2 package is not installed, this is not applicable.

To check the status of the idle screen lock activation, run the following command:

$ gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/lock_enabled

If properly configured, the output should be "true".
If it is not, this is a finding.
'

# START_DESCRIBE V-38638
  tag 'gconf','GConf2','screensaver','lock','idle'
  only_if { package('GConf2').installed? }
  describe command('gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/lock_enabled') do
    its('stdout') { should match "true" }
  end
# END_DESCRIBE V-38638

end
