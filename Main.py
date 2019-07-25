from CreateFeaturesHandler import CreateFeaturesHandler

def main():
    cfh = CreateFeaturesHandler(single_csv=False)
    cfh.compute_features()

if __name__== "__main__":
    main()