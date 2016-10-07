# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38688 - A login banner must be displayed immediately prior to, or as part of, graphical desktop environment login prompts.'

control 'V-38688' do
  impact 0.5
  title 'A login banner must be displayed immediately prior to, or as part of, graphical desktop environment login prompts.'
  desc '
An appropriate warning message reinforces policy awareness during the logon process and facilitates possible legal action against attackers.
'
  tag 'stig','V-38688'
  tag severity: 'medium'
  tag checkid: 'C-46250r3_chk'
  tag fixid: 'F-43637r2_fix'
  tag version: 'RHEL-06-000324'
  tag ruleid: 'SV-50489r3_rule'
  tag fixtext: '
To enable displaying a login warning banner in the GNOME Display Manager\'s login screen, run the following command: 

# gconftool-2 --direct \
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
--type bool \
--set /apps/gdm/simple-greeter/banner_message_enable true

To display a banner, this setting must be enabled and then banner text must also be set.
'
  tag checktext: '
If the GConf2 package is not installed, this is not applicable.

To ensure a login warning banner is enabled, run the following: 

$ gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gdm/simple-greeter/banner_message_enable

Search for the "banner_message_enable" schema. If properly configured, the "default" value should be "true". 
If it is not, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
