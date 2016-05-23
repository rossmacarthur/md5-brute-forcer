CC=gcc
LIBS=
TARGET=main
DEPS=md5.o

$(TARGET): $(DEPS) $(TARGET).o
	$(CC) $^ $(LIBS) -o $@
$(TARGET).o: $(TARGET).c $(DEPS)
	$(CC) -c $< -o $@
$(DEPS): %.o: %.c %.h
	$(CC) -c $< -o $@
run:
	@./$(TARGET)
clean:
	rm -f $(DEPS) $(TARGET).o $(TARGET)
