import { stopwords as mandarinStopwords } from "@orama/stopwords/mandarin";
import { createTokenizer } from "@orama/tokenizers/mandarin";
import { createFromSource } from "fumadocs-core/search/server";
import { source } from "@/lib/source";

const server = createFromSource(source, {
  components: {
    tokenizer: createTokenizer({
      language: "mandarin",
      stopWords: mandarinStopwords,
    }),
  },
});

export async function loader() {
  return server.staticGET();
}
