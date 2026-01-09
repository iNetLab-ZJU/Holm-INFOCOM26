obj-m += holm-module.o
holm-module-y = holm-local-response.o holm-signals.o holm-network-response.o holm-logging.o holm.o
PWD := $(CURDIR)
all:	
		python3 generate_system_params.py
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean		
