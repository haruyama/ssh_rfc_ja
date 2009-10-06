DIST=/home/haruyama/work/SSH/RFC/unixuser.org

all:
	cd target; for i in *; do echo $$i; rfc_fold.rb $$i > $(DIST)/`basename	$$i`; done
