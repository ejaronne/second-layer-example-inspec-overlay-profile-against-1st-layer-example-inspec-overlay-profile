# encoding: utf-8

include_controls "redhat-enterprise-linux-7-stig-baseline" do
  
  control "V-71933" do
    impact 0.0
    desc 'caveat', 'This is Not Applicable for the ACME project since we have an approved risk-based decision on 10/1/2020 in CFACTS allowing reuse of old passwords'
    describe 'This is Not Applicable for the ACME project since we have an approved risk-based decision on 10/1/2020 in CFACTS allowing reuse of old passwords' do
      skip 'This is Not Applicable for the ACME project since we have an approved risk-based decision on 10/1/2020 in CFACTS allowing reuse of old passwords'
    end
  end 
  
  control 'V-71943' do
	title "The ACME Red Hat Enterprise Linux operating system must be configured to lock accounts for a minimum of 60 minutes after TEN unsuccessful logon attempts within a 120-minute timeframe."
	  desc 'caveat', 'The ACME project needs to set this to TEN since we have an approved risk-based decision on 10/2/2020 in CFACTS allowing it'
	  desc 'check', "
	    Check that the ACME system locks an account for a minimum of 60 minutes after
	TEN unsuccessful logon attempts within a period of 120 minutes with the
	following command:
	    # grep pam_faillock.so /etc/pam.d/password-auth
	    auth required pam_faillock.so preauth silent audit deny=10 even_deny_root
	fail_interval=7200 unlock_time=3600
	    auth [default=die] pam_faillock.so authfail audit deny=10 even_deny_root
	fail_interval=7200 unlock_time=3600
	    account required pam_faillock.so
	    If the \"deny\" parameter is set to \"0\" or a value less than \"10\" on
	both \"auth\" lines with the \"pam_faillock.so\" module, or is missing from
	these lines, this is a finding.
	    If the \"even_deny_root\" parameter is not set on both \"auth\" lines with
	the \"pam_faillock.so\" module, or is missing from these lines, this is a
	finding.
	    If the \"fail_interval\" parameter is set to \"0\" or is set to a value
	less than \"7200\" on both \"auth\" lines with the \"pam_faillock.so\" module,
	or is missing from these lines, this is a finding.
	    If the \"unlock_time\" parameter is not set to \"0\", \"never\", or is set
	to a value less than \"3600\" on both \"auth\" lines with the
	\"pam_faillock.so\" module, or is missing from these lines, this is a finding.
	    Note: The maximum configurable value for \"unlock_time\" is \"604800\".
	    If any line referencing the \"pam_faillock.so\" module is commented out,
	this is a finding.
	    # grep pam_faillock.so /etc/pam.d/system-auth
	    auth required pam_faillock.so preauth silent audit deny=10 even_deny_root
	fail_interval=7200 unlock_time=3600
	    auth [default=die] pam_faillock.so authfail audit deny=10 even_deny_root
	fail_interval=7200 unlock_time=3600
	    account required pam_faillock.so
	    If the \"deny\" parameter is set to \"0\" or a value less than \"3\" on
	both \"auth\" lines with the \"pam_faillock.so\" module, or is missing from
	these lines, this is a finding.
	    If the \"even_deny_root\" parameter is not set on both \"auth\" lines with
	the \"pam_faillock.so\" module, or is missing from these lines, this is a
	finding.
	    If the \"fail_interval\" parameter is set to \"0\" or is set to a value
	less than \"7200\" on both \"auth\" lines with the \"pam_faillock.so\" module,
	or is missing from these lines, this is a finding.
	    If the \"unlock_time\" parameter is not set to \"0\", \"never\", or is set
	to a value less than \"3600\" on both \"auth\" lines with the
	\"pam_faillock.so\" module or is missing from these lines, this is a finding.
	    Note: The maximum configurable value for \"unlock_time\" is \"604800\".
	    If any line referencing the \"pam_faillock.so\" module is commented out,
	this is a finding.
	  "
	  desc  'fix', "
	    Configure the ACME operating system to lock an account for 60 minutes
	when TEN unsuccessful logon attempts in 120 minutes are made.
	    Modify the first three lines of the auth section and the first line of the
	account section of the \"/etc/pam.d/system-auth\" and
	\"/etc/pam.d/password-auth\" files to match the following lines:
	    auth required pam_faillock.so preauth silent audit deny=10 even_deny_root
	fail_interval=7200 unlock_time=3600
	    auth sufficient pam_unix.so try_first_pass
	    auth [default=die] pam_faillock.so authfail audit deny=10 even_deny_root
	fail_interval=7200 unlock_time=3600
	    account required pam_faillock.so
	    Note: Manual changes to the listed files may be overwritten by the
	\"authconfig\" program. The \"authconfig\" program should not be used to update
	the configurations listed in this requirement.
	  "
	end

    
end
