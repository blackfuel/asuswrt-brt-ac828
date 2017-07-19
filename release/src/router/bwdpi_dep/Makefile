include ../common.mak

all:
	@cd bwdpi/ && $(MAKE)
	@cd bwdpi_sqlite/ && $(MAKE)
	@cd bwdpi_monitor/ && $(MAKE)
	@cd bwdpi_bin/ && $(MAKE)

install: all
	@cd bwdpi/ && $(MAKE) install
	@cd bwdpi_sqlite/ && $(MAKE) install
	@cd bwdpi_monitor/ && $(MAKE) install
	@cd bwdpi_bin/ && $(MAKE) install

clean:
	@cd bwdpi/ && $(MAKE) clean
	@cd bwdpi_sqlite/ && $(MAKE) clean
	@cd bwdpi_monitor/ && $(MAKE) clean
