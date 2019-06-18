SAGEFILES := $(basename $(notdir $(wildcard *.sage)))
PYFILES := $(addprefix __sage__, $(addsuffix .py,$(SAGEFILES)))
.PRECIOUS: $(PYFILES)


.PHONY: pyfiles
pyfiles: $(PYFILES)

__sage__%.py: %.sage
	@echo "Parsing $<"
	@sage --preparse $<
	@mv $<.py $@



clean:
	rm -f __sage__*.py *.pyc *.sage.py *.log
