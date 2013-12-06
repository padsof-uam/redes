GCC = g++
# CPPFLAGS = -ggdb -Wall -pedantic -std=c++98
# Quitamos warnings porque el código que nos han dado está lleno de warnings por todas partes.
CPPFLAGS = -ggdb 
LIBS = -lpcap
TARGET = practica4

OBJDIR = obj
SRCDIR = src
BINDIR = bin

SRCS := $(wildcard $(SRCDIR)/*.cpp)
OBJS := $(addprefix $(OBJDIR)/, $(patsubst %.cpp,%.o, $(SRCS)))

.PRECIOUS: %.o %.d
.PHONY: debug clean 
 
debug: $(TARGET)
scan: clean
	@scan-build make
$(OBJS): | $(OBJDIR)

depend: $(OBJDIR)/.deps

$(OBJDIR)/.deps: $(SRCS) | $(OBJDIR)
	@-rm -f $(OBJDIR)/.deps
	@$(CC) $(CFLAGS) -MM $^ >> $(OBJDIR)/.deps;
	@awk '{printf("$(OBJDIR)/$(SRCDIR)/%s\n", $$0)}' $@ > "$@.0"
	@mv "$@.0" $@

-include $(OBJDIR)/.deps

$(TARGET): $(OBJDIR)/src/$(TARGET).o $(OBJS) | $(BINDIR) depend
	@echo Building final target: $@
	@$(GCC) $(CPPFLAGS) -o $(BINDIR)/$@ $^ $(LIBS)
$(OBJDIR)/%.o: %.cpp | $(OBJDIR) depend
	@echo "$< -> $@"
	@$(GCC) $(CPPFLAGS) -c $< -o $@
$(OBJDIR):
	@echo Creating obj directories
	@mkdir -p $(OBJDIR)
	@mkdir -p $(OBJDIR)/$(SRCDIR)
$(BINDIR):
	@echo Creating bin directory
	@mkdir $(BINDIR)
clean: 
	-rm -rf $(OBJDIR) $(BINDIR) $(TARGET) 