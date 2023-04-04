from CreateFeaturesHandler import CreateFeaturesHandler

def main():
    cfh = CreateFeaturesHandler(single_csv=False)
    cfh.compute_features(threads=1)

if __name__== "__main__":
    main()