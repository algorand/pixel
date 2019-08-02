import filecmp

def test_vector():

    for i in range(1,64):


        # output sk to a human readable file
        fname = "test_vector/test_vector/sig_bin_%02d.txt"%i
        fname2 = "test_buf/sig_bin_%02d.txt"%i

        assert filecmp.cmp(fname, fname2)


if __name__ == "__main__":
    def main():
        test_vector()
    main()
