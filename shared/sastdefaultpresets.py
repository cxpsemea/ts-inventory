
# Default presets configurations, out-of-the box
# Depending on version

def sastdefaultpresets( sastversion: None ) :
    # from SAST 9.6.1
    if not sastversion or sastversion['enginePack'].startswith('9.6.1') :
        from sastdefaultpresets961 import default_presets_961
        return default_presets_961
    # from SAST 9.6.0
    if not sastversion or sastversion['enginePack'].startswith('9.6.0') :
        from sastdefaultpresets960 import default_presets_960
        return default_presets_960
    # from SAST 9.5.5
    if not sastversion or sastversion['enginePack'].startswith('9.5.5') :
        from sastdefaultpresets955 import default_presets_955
        return default_presets_955
    # from SAST 9.5.4
    elif sastversion['enginePack'].startswith('9.5.4') :
        from sastdefaultpresets954 import default_presets_954
        return default_presets_954
    # from SAST 9.5.3
    elif sastversion['enginePack'].startswith('9.5.3') :
        from sastdefaultpresets953 import default_presets_953
        return default_presets_953
    # from SAST 9.5.0
    elif sastversion['version'].startswith('9.5.0') :
        from sastdefaultpresets950 import default_presets_950
        return default_presets_950
    # from SAST 9.4.5
    elif sastversion['enginePack'].startswith('9.4.5') :
        from sastdefaultpresets945 import default_presets_945
        return default_presets_945
    # from SAST 9.4.0
    elif sastversion['version'].startswith('9.4.0') :
        from sastdefaultpresets940 import default_presets_940
        return default_presets_940
    # from SAST 9.3.0
    elif sastversion['version'].startswith('9.3.0') :
        from sastdefaultpresets930 import default_presets_930
        return default_presets_930
    # anything else, use the lastest
    else :
        from sastdefaultpresets961 import default_presets_961
        return default_presets_961
