# Builds libi2pd.a out of tree: make -f mayhem/lib.mk OUT=<dir> LIB_CXXFLAGS='<flags>' [-j N]
SRCS := $(wildcard libi2pd/*.cpp)
OBJS := $(patsubst libi2pd/%.cpp,$(OUT)/obj/%.o,$(SRCS))

$(OUT)/libi2pd.a: $(OBJS)
	rm -f $@
	$(AR) rcs $@ $^

$(OUT)/obj/%.o: libi2pd/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(LIB_CXXFLAGS) -std=c++20 -fPIC -Wno-psabi -DOPENSSL_SUPPRESS_DEPRECATED \
	  -D_GLIBCXX_USE_NANOSLEEP=1 -Ilibi2pd -Ii18n -c -o $@ $<
