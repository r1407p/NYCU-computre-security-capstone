GXX = g++
CXXFLAGS = -std=c++17 -lpthread -lnetfilter_queue
basic_sources = attacker.cpp
sources = mitm_attack.cpp 
sources2 = pharm_attack.cpp
target = mitm_attack
target2 = pharm_attack
debug_target = mitm_attack_debug

all: $(target) $(target2)

$(target): $(sources) 
	$(GXX) $(CXXFLAGS) -o $(target) $(sources) $(basic_sources)

$(target2): $(sources2)
	$(GXX) $(CXXFLAGS) -o $(target2) $(sources2) $(basic_sources)
debug: CXXFLAGS += -DDEBUG -g
debug: $(debug_target)

$(debug_target): $(sources)
	$(GXX) $(CXXFLAGS) -o $(debug_target) $(sources)

clean:
	rm -f $(target) $(debug_target) $(target2)