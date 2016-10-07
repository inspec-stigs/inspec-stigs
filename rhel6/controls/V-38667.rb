# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38667 - The system must have a host-based intrusion detection tool installed.'

control 'V-38667' do
  impact 0.5
  title 'The system must have a host-based intrusion detection tool installed.'
  desc '
Adding host-based intrusion detection tools can provide the capability to automatically take actions in response to malicious behavior, which can provide additional agility in reacting to network threats. These tools also often include a reporting capability to provide network awareness of system, which may not otherwise exist in an organization\'s systems management regime.
'
  tag 'stig','V-38667'
  tag severity: 'medium'
  tag checkid: 'C-46227r1_chk'
  tag fixid: 'F-43616r2_fix'
  tag version: 'RHEL-06-000285'
  tag ruleid: 'SV-50468r2_rule'
  tag fixtext: '
The base Red Hat platform already includes a sophisticated auditing system that can detect intruder activity, as well as SELinux, which provides host-based intrusion prevention capabilities by confining privileged programs and user sessions which may become compromised.

In DoD environments, supplemental intrusion detection tools, such as, the McAfee Host-based Security System, are available to integrate with existing infrastructure. When these supplemental tools interfere with the proper functioning of SELinux, SELinux takes precedence. 
'
  tag checktext: '
Inspect the system to determine if intrusion detection software has been installed. Verify the intrusion detection software is active. 
If no host-based intrusion detection tools are installed, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
