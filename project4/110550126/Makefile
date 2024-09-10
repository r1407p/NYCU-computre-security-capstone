CXX = gcc
SRCS = my_magic.c
EXEC = I-1.py I-2.py I-3.py I-4.py II-1.py II-2.py
OBJS = $(SRCS:.c=.out)

all: $(OBJS)

$(OBJS): $(SRCS)
	$(CXX) $< -o $@
	chmod +x $(EXEC)

clean:
	rm -f $(OBJS)
