# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38462 - The RPM package management tool must cryptographically verify the authenticity of all software packages during installation.'

control 'V-38462' do
  impact 1.0
  title 'The RPM package management tool must cryptographically verify the authenticity of all software packages during installation.'
  desc '
Ensuring all packages\' cryptographic signatures are valid prior to installation ensures the provenance of the software and protects against malicious tampering.
'
  tag 'stig','V-38462'
  tag severity: 'high'
  tag checkid: 'C-46017r1_chk'
  tag fixid: 'F-43407r1_fix'
  tag version: 'RHEL-06-000514'
  tag ruleid: 'SV-50262r1_rule'
  tag fixtext: '
Edit the RPM configuration files containing the "nosignature" option and remove the option.
'
  tag checktext: '
Verify RPM signature validation is not disabled:
# grep nosignature /etc/rpmrc /usr/lib/rpm/rpmrc /usr/lib/rpm/redhat/rpmrc ~root/.rpmrc
If any configuration is found, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
