# Running M3 on Google Colab

Runtime → Change runtime type → **T4 GPU**. Code stays in the repo; the notebook only launches it.

```python
from google.colab import drive
drive.mount('/content/drive')

!git clone -b <your-branch> https://github.com/<org>/<repo>.git
%cd <repo>
!pip install -q pyarrow          # Colab already has torch, pandas, sklearn

# Data lives on Drive so it survives the session
!mkdir -p data && ln -sfn /content/drive/MyDrive/ict3214/processed data/processed

!python -m eval.run --model m3 --exp E2 --epochs 1 --max-rows 20000   # smoke test first
!python -m eval.run --model m3 --exp E2                               # full run
!python -m eval.summarise

# Keep outputs: copy back to Drive (or commit results/ from your laptop)
!cp -r results artifacts /content/drive/MyDrive/ict3214/
```

If you push from Colab, put a GitHub token in Colab's **Secrets** panel. Never paste it into a cell.
