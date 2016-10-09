# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38603 - The ypserv package must not be installed.'

control 'V-38603' do
  impact 0.5
  title 'The ypserv package must not be installed.'
  desc '
Removing the "ypserv" package decreases the risk of the accidental (or intentional) activation of NIS or NIS+ services.
'
  tag 'stig','V-38603'
  tag severity: 'medium'
  tag checkid: 'C-46161r1_chk'
  tag fixid: 'F-43551r1_fix'
  tag version: 'RHEL-06-000220'
  tag ruleid: 'SV-50404r1_rule'
  tag fixtext: '
The "ypserv" package can be uninstalled with the following command:

# yum erase ypserv
'
  tag checktext: '
Run the following command to determine if the "ypserv" package is installed:

# rpm -q ypserv


If the package is installed, this is a finding.
'

# START_DESCRIBE V-38603
  describe package('ypserv') do
    it { should_not be_installed }
  end
# END_DESCRIBE V-38603

end
