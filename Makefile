GCC = $(CC)
CFLAGS = -ggdb -std=gnu99 -Wall -pedantic
TARGET = mkt

OBJDIR = obj
SRCDIR = src
BINDIR = bin

OBJS := $(addprefix $(OBJDIR)/, $(patsubst %.c,%.o, $(wildcard $(SRCDIR)/*.c)))

.PRECIOUS: %.o 
.PHONY: debug clean 
 
debug: $(TARGET)
scan: clean
	@scan-build make
$(OBJS): | $(OBJDIR)

$(TARGET): $(OBJDIR)/src/main.o $(OBJS) | $(BINDIR)
	@echo Building final target: $@
	@$(GCC) $(CFLAGS) -o $(BINDIR)/$@ $^
$(OBJDIR)/%.o: %.c | $(OBJDIR)
	@echo "$< -> $@"
	@$(GCC) $(CFLAGS) -c $< -o $@
$(OBJDIR):
	@echo Creating obj directories
	@mkdir -p $(OBJDIR)
	@mkdir -p $(OBJDIR)/$(SRCDIR)
$(BINDIR):
	@echo Creating bin directory
	@mkdir $(BINDIR)
clean: 
	-rm -rf $(OBJDIR) $(BINDIR) $(TARGET) 
