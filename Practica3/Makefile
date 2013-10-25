GCC = g++
CPPFLAGS = -ggdb -Wall -pedantic
LIBS = -lpcap
TARGET = main

OBJDIR = obj
SRCDIR = src
BINDIR = bin

OBJS := $(addprefix $(OBJDIR)/, $(patsubst %.cpp,%.o, $(wildcard $(SRCDIR)/*.cpp)))

.PRECIOUS: %.o 
.PHONY: debug clean 
 
debug: $(TARGET)
scan: clean
	@scan-build make
$(OBJS): | $(OBJDIR)

$(TARGET): $(OBJDIR)/src/main.o $(OBJS) | $(BINDIR)
	@echo Building final target: $@
	@$(GCC) $(CPPFLAGS) -o $(BINDIR)/$@ $^ $(LIBS)
$(OBJDIR)/%.o: %.cpp | $(OBJDIR)
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
