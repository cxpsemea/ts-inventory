
# Default query categories, out-of-the box
# Depending on version

def sastdefaultcategories( sastversion: None ) :
    # from SAST 9.6.7
    if not sastversion or sastversion['enginePack'].startswith('9.6.7') :
        from sastdefaultcategories967 import default_categories_967
        return default_categories_967
    # from SAST 9.6.6
    if not sastversion or sastversion['enginePack'].startswith('9.6.6') :
        from sastdefaultcategories966 import default_categories_966
        return default_categories_966
    # from SAST 9.6.5
    if not sastversion or sastversion['enginePack'].startswith('9.6.5') :
        from sastdefaultcategories965 import default_categories_965
        return default_categories_965
    # from SAST 9.6.4
    if not sastversion or sastversion['enginePack'].startswith('9.6.4') :
        from sastdefaultcategories964 import default_categories_964
        return default_categories_964
    # from SAST 9.6.3
    if not sastversion or sastversion['enginePack'].startswith('9.6.3') :
        from sastdefaultcategories963 import default_categories_963
        return default_categories_963
    # from SAST 9.6.2
    if not sastversion or sastversion['enginePack'].startswith('9.6.2') :
        from sastdefaultcategories962 import default_categories_962
        return default_categories_962
    # from SAST 9.6.1
    if not sastversion or sastversion['enginePack'].startswith('9.6.1') :
        from sastdefaultcategories961 import default_categories_961
        return default_categories_961
    # from SAST 9.6.0
    if not sastversion or sastversion['enginePack'].startswith('9.6.0') :
        from sastdefaultcategories960 import default_categories_960
        return default_categories_960
    # from SAST 9.5.5
    if not sastversion or sastversion['enginePack'].startswith('9.5.5') :
        from sastdefaultcategories955 import default_categories_955
        return default_categories_955
    # from SAST 9.5.4
    elif sastversion['enginePack'].startswith('9.5.4') :
        from sastdefaultcategories954 import default_categories_954
        return default_categories_954
    # from SAST 9.5.3
    elif sastversion['enginePack'].startswith('9.5.3') :
        from sastdefaultcategories953 import default_categories_953
        return default_categories_953
    # from SAST 9.5.0
    elif sastversion['version'].startswith('9.5.0') :
        from sastdefaultcategories950 import default_categories_950
        return default_categories_950
    # from SAST 9.4.5
    elif sastversion['enginePack'].startswith('9.4.5') :
        from sastdefaultcategories945 import default_categories_945
        return default_categories_945
    # from SAST 9.4.0
    elif sastversion['version'].startswith('9.4.0') :
        from sastdefaultcategories940 import default_categories_940
        return default_categories_940
    # from SAST 9.3.0
    elif sastversion['version'].startswith('9.3.0') :
        from sastdefaultcategories930 import default_categories_930
        return default_categories_930
    # anything else, use the lastest
    else :
        from sastdefaultcategories967 import default_categories_967
        return default_categories_967
