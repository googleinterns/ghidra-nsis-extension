package nsis.file;

import java.util.HashMap;
import java.util.Map;

public class NsisLangTableMapper {
  private Map<Integer,Map<Integer,Integer>> langs = new HashMap<Integer,Map<Integer,Integer>>();
  private int defaultLangID = -1;
  
  public NsisLangTableMapper(int defaultLangID) {
    this.defaultLangID = defaultLangID;
  }
  
  public NsisLangTableMapper() {
  }

  public Integer getStringOffset(int langID, int idx) {
    if (this.langs.containsKey(langID) && this.langs.get(langID).containsKey(idx)) {
      return langs.get(langID).get(idx);
    }
    return null;
  }
  
  public Integer getStringOffset(int idx) {
    return getStringOffset(this.defaultLangID, idx);
  }
  
  public void addStringOffset(int langID, int idx, int stringOffset) {
    if (defaultLangID == -1) {
      this.defaultLangID = langID;
    }
    
    if (!this.langs.containsKey(langID)) {
      this.langs.put(langID, new HashMap<Integer, Integer>());
    }
    this.langs.get(langID).put(idx, stringOffset);
  }
}
