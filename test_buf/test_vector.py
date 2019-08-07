import filecmp

def test_vector():
    for i in range(1,64):
        # compare the signatures
        fname = "test_vector/test_vector/sig_bin_%02d.txt"%i
        fname2 = "test_buf/sig_bin_%02d.txt"%i
        assert filecmp.cmp(fname, fname2)
        # compare the secret keys
        fname = "test_vector/test_vector/sk_bin_%02d.txt"%i
        fname2 = "test_buf/sk_bin_%02d.txt"%i
        assert filecmp.cmp(fname, fname2)


if __name__ == "__main__":
    def main():
        test_vector()
    main()
